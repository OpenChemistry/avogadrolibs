/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "fileformat.h"

#include "compressedstream.h"
#include "compression.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <locale>
#include <memory>
#include <sstream>

namespace Avogadro::Io {

using std::ifstream;
using std::locale;
using std::ofstream;

using json = nlohmann::json;

namespace {

// Options are supplied as a JSON object. Parsing with exceptions disabled
// yields a discarded value for anything malformed, and the lookups below must
// not throw, so everything that is not an object becomes an empty object.
json parseOptions(const std::string& options)
{
  json opts = json::parse(options, nullptr, false);
  return opts.is_object() ? opts : json::object();
}

} // namespace

FileFormat::FileFormat()
  : m_mode(None), m_in(nullptr), m_out(nullptr), m_decompressor(nullptr),
    m_compressor(nullptr), m_outputError(false)
{
}

FileFormat::~FileFormat()
{
  delete m_in;
  delete m_out;
}

bool FileFormat::validateFileName(const std::string& fileName)
{
  bool valid = !fileName.empty();

  if (valid) {
    // check if the filename contains invalid characters
    static std::string forbiddenChars(",^@={}[]~!?:&*\"|#%<>$\"'();`'");
    valid = fileName.find_first_of(forbiddenChars) == std::string::npos;

    // check if the filename contains ".." which we should not allow
    valid = valid && fileName.find("..") == std::string::npos;
  }

  // Finally check against Windows names
  // .. we do this on all platforms because CON.cif, for example
  // is problematic to send to a Windows user.
  if (valid) {
    static std::string forbiddenNames(
      "CON PRN AUX NUL COM1 COM2 COM3 COM4 COM5 "
      "COM6 COM7 COM8 COM9 LPT1 LPT2 LPT3 LPT4 "
      "LPT5 LPT6 LPT7 LPT8 LPT9");
    // case insensitive search, since con.txt is also a problem
    // https://stackoverflow.com/a/19839371/131896
    auto it = std::search(fileName.begin(), fileName.end(),
                          forbiddenNames.begin(), forbiddenNames.end(),
                          [](unsigned char ch1, unsigned char ch2) {
                            return std::toupper(ch1) == std::toupper(ch2);
                          });
    valid = (it == fileName.end());
  }

  return valid;
}

bool FileFormat::open(const std::string& fileName_, Operation mode_)
{
  close();
  // close() can set this, so clear it after closing rather than before: a
  // failure to flush a previous compressed write must not make the next
  // writeFile() on this same instance report failure.
  m_outputError = false;
  m_fileName = fileName_;
  m_mode = mode_;
  if (!m_fileName.empty()) {
    // Imbue the standard C locale.
    locale cLocale("C");
    if (m_mode & Read) {
      auto file =
        std::make_unique<ifstream>(m_fileName.c_str(), std::ifstream::binary);
      if (!file->is_open()) {
        appendError("Error opening file: " + fileName_);
        return false;
      }
      file->imbue(cLocale);

      const long long maxDecoded = maxDecompressedSizeOption();

      std::string wrapError;
      std::unique_ptr<std::istream> wrapped =
        wrapIfCompressed(std::unique_ptr<std::istream>(file.release()),
                         wrapError, static_cast<std::uint64_t>(maxDecoded));
      if (!wrapped) {
        appendError(fileName_ + ": " + wrapError);
        return false;
      }
      wrapped->imbue(cLocale);
      m_decompressor = dynamic_cast<DecompressingIStream*>(wrapped.get());
      m_in = wrapped.release();
      return true;
    } else if (m_mode & Write) {
      Compression type = Compression::None;
      stripCompressionSuffix(m_fileName, &type);
      if (type != Compression::None && !compressionSupported(type)) {
        appendError("Cannot write " + m_fileName + ": " +
                    compressionName(type) +
                    " compression is not supported "
                    "in this build.");
        return false;
      }

      auto file =
        std::make_unique<ofstream>(m_fileName.c_str(), std::ofstream::binary);
      if (!file->is_open()) {
        appendError("Error opening file: " + fileName_);
        return false;
      }
      file->imbue(cLocale);

      if (type != Compression::None) {
        auto compressing = std::make_unique<CompressingOStream>(
          std::unique_ptr<std::ostream>(file.release()), type);
        // CompressingOStream does not inherit the underlying file stream's
        // locale (they are separate std::ios objects), and it is what
        // write() actually formats numbers into, so imbue it explicitly.
        compressing->imbue(cLocale);
        m_compressor = compressing.get();
        m_out = compressing.release();
      } else {
        m_out = file.release();
      }
      return true;
    }
  }
  return false;
}

void FileFormat::close()
{
  if (m_compressor) {
    if (!m_compressor->finish()) {
      appendError(m_compressor->error());
      m_outputError = true;
    }
  }
  m_decompressor = nullptr;
  m_compressor = nullptr;
  if (m_in) {
    delete m_in;
    m_in = nullptr;
  }
  if (m_out) {
    delete m_out;
    m_out = nullptr;
  }
  m_mode = None;
}

bool FileFormat::readMolecule(Core::Molecule& molecule)
{
  if (!m_in)
    return false;
  bool result = read(*m_in, molecule);
  // A decode failure (truncation, a bad checksum, the size limit) surfaces to
  // the reader as an ordinary end of stream, which most parsers treat as a
  // short but otherwise valid file -- so a truncated "molecule.xyz.gz" would
  // otherwise silently yield a short but "successful" molecule. Check the
  // decompressor's own error state explicitly, regardless of what read()
  // returned.
  if (m_decompressor && !m_decompressor->error().empty()) {
    appendError(m_decompressor->error());
    return false;
  }
  return result;
}

bool FileFormat::writeMolecule(const Core::Molecule& molecule)
{
  if (!m_out)
    return false;
  return write(*m_out, molecule);
}

bool FileFormat::readFile(const std::string& fileName_,
                          Core::Molecule& molecule)
{
  bool result = open(fileName_, Read);
  if (!result)
    return false;

  result = readMolecule(molecule);
  close();
  return result;
}

bool FileFormat::writeFile(const std::string& fileName_,
                           const Core::Molecule& molecule)
{
  bool result = open(fileName_, Write);
  if (!result)
    return false;

  result = writeMolecule(molecule);
  close();
  return result && !m_outputError;
}

bool FileFormat::readString(const std::string& string, Core::Molecule& molecule)
{
  // Compression is detected from content, not from the (absent) file name
  // here, so a caller passing plain "xyz" as the extension still gets gzip
  // data decoded transparently. wrapIfCompressed() passes plain data straight
  // through, so this costs one small read in the overwhelmingly common
  // uncompressed case.
  const long long maxDecoded = maxDecompressedSizeOption();

  auto source =
    std::make_unique<std::istringstream>(string, std::istringstream::in);
  std::string wrapError;
  std::unique_ptr<std::istream> wrapped =
    wrapIfCompressed(std::unique_ptr<std::istream>(source.release()), wrapError,
                     static_cast<std::uint64_t>(maxDecoded));
  if (!wrapped) {
    appendError(wrapError);
    return false;
  }

  // Imbue the standard C locale.
  locale cLocale("C");
  wrapped->imbue(cLocale);

  auto* decompressor = dynamic_cast<DecompressingIStream*>(wrapped.get());
  bool result = read(*wrapped, molecule);
  // See the comment in readMolecule(): a decode failure surfaces as an
  // ordinary end of stream, so it must be checked explicitly.
  if (decompressor && !decompressor->error().empty()) {
    appendError(decompressor->error());
    return false;
  }
  return result;
}

bool FileFormat::writeString(std::string& string,
                             const Core::Molecule& molecule)
{
  // Note: the stream must not be seeded with @a string. Doing so overwrites
  // from position 0 without truncating, so any part of a previous (longer)
  // value would survive past the end of the new one.
  std::ostringstream stream;
  // Imbue the standard C locale.
  locale cLocale("C");
  stream.imbue(cLocale);
  bool result = write(stream, molecule);
  string = stream.str();
  return result;
}

void FileFormat::clear()
{
  // Resetting means resetting: close whatever is still open first, so a
  // compressed write is finalised and its trailer written rather than
  // abandoned, and no alias pointer outlives the stream it points into.
  // close() takes care of m_in, m_out, m_decompressor, m_compressor and the
  // mode; everything below is this class's own bookkeeping.
  close();
  m_fileName.clear();
  m_error.clear();
  m_outputError = false;
}

void FileFormat::appendError(const std::string& errorString, bool newLine)
{
  m_error += errorString;
  if (newLine)
    m_error += "\n";
}

bool FileFormat::boolOption(const std::string& name, bool& value)
{
  const json opts = parseOptions(m_options);
  const auto match = opts.find(name);
  if (match == opts.end())
    return true;

  if (!match->is_boolean()) {
    appendError("The \"" + name + "\" option must be a boolean.");
    return false;
  }
  value = match->get<bool>();
  return true;
}

bool FileFormat::stringOption(const std::string& name, std::string& value)
{
  const json opts = parseOptions(m_options);
  const auto match = opts.find(name);
  if (match == opts.end())
    return true;

  if (!match->is_string()) {
    appendError("The \"" + name + "\" option must be a string.");
    return false;
  }
  value = match->get<std::string>();
  return true;
}

bool FileFormat::stringArrayOption(const std::string& name,
                                   std::vector<std::string>& values)
{
  const json opts = parseOptions(m_options);
  const auto match = opts.find(name);
  if (match == opts.end())
    return true;

  if (!match->is_array()) {
    appendError("The \"" + name + "\" option must be an array of strings.");
    return false;
  }

  // Only assign once every element checks out, so a bad entry leaves the
  // caller's defaults alone rather than a partially filled list.
  std::vector<std::string> parsed;
  parsed.reserve(match->size());
  for (const auto& element : *match) {
    if (!element.is_string()) {
      appendError("The \"" + name + "\" option must be an array of strings.");
      return false;
    }
    parsed.push_back(element.get<std::string>());
  }
  values = std::move(parsed);
  return true;
}

long long FileFormat::maxDecompressedSizeOption()
{
  auto value = static_cast<long long>(defaultMaxDecompressedSize);
  integerOption("maxDecompressedSize", value);
  if (value < 0) {
    appendError("The \"maxDecompressedSize\" option must not be negative.");
    value = static_cast<long long>(defaultMaxDecompressedSize);
  }
  return value;
}

bool FileFormat::integerOption(const std::string& name, long long& value)
{
  const json opts = parseOptions(m_options);
  const auto match = opts.find(name);
  if (match == opts.end())
    return true;

  if (!match->is_number_integer()) {
    appendError("The \"" + name + "\" option must be an integer.");
    return false;
  }
  value = match->get<long long>();
  return true;
}

} // namespace Avogadro::Io
