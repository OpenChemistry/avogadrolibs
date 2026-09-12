/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "fileformatmanager.h"

#include "compressedstream.h"
#include "compression.h"
#include "fileformat.h"

#include "cjsonformat.h"
#include "cmlformat.h"
#include "dcdformat.h"
#include "gromacsformat.h"
#include "lammpsformat.h"
#include "mdlformat.h"
#include "pdbformat.h"
#include "sdfformat.h"
#include "smilesformat.h"
#include "trrformat.h"
#include "turbomoleformat.h"
#include "vaspformat.h"
#include "xyzformat.h"

#ifdef AVO_USE_MMTF
#include "mmtfformat.h"
#endif

#include <algorithm>
#include <memory>
#include <sstream>

using std::unique_ptr;

namespace Avogadro::Io {

FileFormatManager& FileFormatManager::instance()
{
  static FileFormatManager instance;
  return instance;
}

bool FileFormatManager::readFile(Core::Molecule& molecule,
                                 const std::string& fileName,
                                 const std::string& fileExtension,
                                 const std::string& options) const
{
  // error() reports the most recent operation, so start clean.
  m_error.clear();

  FileFormat* format(nullptr);
  if (fileExtension.empty()) {
    // We need to guess the file extension. Strip a compression suffix first
    // (".gz", ".bz2", ...) so that "molecule.xyz.gz" resolves by its
    // chemical extension "xyz", not by the codec's own extension.
    std::string stripped = stripCompressionSuffix(fileName);
    size_t pos = stripped.find_last_of('.');
    format = filteredFormatFromFormatMap(stripped.substr(pos + 1),
                                         FileFormat::Read | FileFormat::File,
                                         m_fileExtensions);
  } else {
    format = filteredFormatFromFormatMap(stripCompressionSuffix(fileExtension),
                                         FileFormat::Read | FileFormat::File,
                                         m_fileExtensions);
  }
  if (!format) {
    appendError("No file format available to read \"" + fileName + "\".");
    return false;
  }

  unique_ptr<FileFormat> formatInstance(format->newInstance());
  formatInstance->setOptions(options);
  if (formatInstance->readFile(fileName, molecule))
    return true;
  appendError(formatInstance->error());
  return false;
}

bool FileFormatManager::writeFile(const Core::Molecule& molecule,
                                  const std::string& fileName,
                                  const std::string& fileExtension,
                                  const std::string& options) const
{
  // error() reports the most recent operation, so start clean.
  m_error.clear();

  FileFormat* format(nullptr);
  if (fileExtension.empty()) {
    // We need to guess the file extension. Strip a compression suffix first
    // (".gz", ".bz2", ...) so that "molecule.xyz.gz" resolves by its
    // chemical extension "xyz", not by the codec's own extension.
    std::string stripped = stripCompressionSuffix(fileName);
    size_t pos = stripped.find_last_of('.');
    format = filteredFormatFromFormatMap(stripped.substr(pos + 1),
                                         FileFormat::Write | FileFormat::File,
                                         m_fileExtensions);
  } else {
    format = filteredFormatFromFormatMap(stripCompressionSuffix(fileExtension),
                                         FileFormat::Write | FileFormat::File,
                                         m_fileExtensions);
  }
  if (!format) {
    appendError("No file format available to write \"" + fileName + "\".");
    return false;
  }

  unique_ptr<FileFormat> formatInstance(format->newInstance());
  formatInstance->setOptions(options);
  if (formatInstance->writeFile(fileName, molecule))
    return true;
  appendError(formatInstance->error());
  return false;
}

bool FileFormatManager::readString(Core::Molecule& molecule,
                                   const std::string& string,
                                   const std::string& fileExtension,
                                   const std::string& options) const
{
  // error() reports the most recent operation, so start clean.
  m_error.clear();

  // The extension only selects the format here; the actual decoding is
  // content-driven inside FileFormat::readString().
  FileFormat* format(filteredFormatFromFormatMap(
    stripCompressionSuffix(fileExtension),
    FileFormat::Read | FileFormat::String, m_fileExtensions));
  if (!format) {
    appendError("No file format available to read \"" + fileExtension +
                "\" content.");
    return false;
  }

  unique_ptr<FileFormat> formatInstance(format->newInstance());
  formatInstance->setOptions(options);
  if (formatInstance->readString(string, molecule))
    return true;
  appendError(formatInstance->error());
  return false;
}

bool FileFormatManager::writeString(const Core::Molecule& molecule,
                                    std::string& string,
                                    const std::string& fileExtension,
                                    const std::string& options) const
{
  // error() reports the most recent operation, so start clean.
  m_error.clear();

  Compression type = Compression::None;
  std::string chemicalExtension = stripCompressionSuffix(fileExtension, &type);
  FileFormat* format(filteredFormatFromFormatMap(
    chemicalExtension, FileFormat::Write | FileFormat::String,
    m_fileExtensions));
  if (!format) {
    appendError("No file format available to write \"" + fileExtension +
                "\" content.");
    return false;
  }

  unique_ptr<FileFormat> formatInstance(format->newInstance());
  formatInstance->setOptions(options);

  if (type == Compression::None) {
    if (formatInstance->writeString(string, molecule))
      return true;
    appendError(formatInstance->error());
    return false;
  }

  if (!compressionSupported(type)) {
    appendError("Cannot write \"" + fileExtension +
                "\": " + compressionName(type) +
                " compression is not supported in this build.");
    return false;
  }

  // writeString() only ever produces uncompressed text (it has no file name
  // to derive a codec from), so compress the result here when the extension
  // named one. CompressingOStream owns its sink, so the sink's contents must
  // be read while the compressing stream is still alive, and only after
  // finish() -- reading them after the compressing stream is destroyed would
  // be a use-after-free of the string it moved out of the ostringstream.
  std::string uncompressed;
  if (!formatInstance->writeString(uncompressed, molecule)) {
    appendError(formatInstance->error());
    return false;
  }

  auto sink = std::make_unique<std::ostringstream>();
  auto* rawSink = sink.get();
  CompressingOStream compressor(std::move(sink), type);
  compressor.write(uncompressed.data(),
                   static_cast<std::streamsize>(uncompressed.size()));
  if (!compressor.finish()) {
    appendError(compressor.error());
    return false;
  }
  string = rawSink->str();
  return true;
}

bool FileFormatManager::registerFormat(FileFormat* format)
{
  return instance().addFormat(format);
}

bool FileFormatManager::unregisterFormat(const std::string& identifier)
{
  return instance().removeFormat(identifier);
}

bool FileFormatManager::addFormat(FileFormat* format)
{
  if (!format) {
    appendError("Supplied format was null.");
    return false;
  }
  if (m_identifiers.count(format->identifier()) > 0) {
    appendError("Format " + format->identifier() + " already loaded.");
    return false;
  }
  for (auto& m_format : m_formats) {
    if (m_format == format) {
      appendError("The format object was already loaded.");
      return false;
    }
  }

  // If we got here then the format is unique enough to be added.
  size_t index = m_formats.size();
  m_formats.push_back(format);
  m_identifiers[format->identifier()].push_back(index);
  std::vector<std::string> mimes = format->mimeTypes();
  for (auto& mime : mimes) {
    m_mimeTypes[mime].push_back(index);
  }
  std::vector<std::string> extensions = format->fileExtensions();
  for (auto& extension : extensions) {
    m_fileExtensions[extension].push_back(index);
  }

  return true;
}

namespace {
// Lookup each key from "keys" in "map", and remove "val" from the Map's
// data value (which is a vector of ValueType)
template <typename Map, typename VectorOfKeys, typename ValueType>
void removeFromMap(Map& map, const VectorOfKeys& keys, const ValueType& val)
{
  for (auto key = keys.begin(), keyEnd = keys.end(); key != keyEnd; ++key) {
    auto mapMatch = map.find(*key);
    if (mapMatch == map.end())
      continue;
    typename Map::mapped_type& vec = mapMatch->second;
    if (vec.size() <= 1) {
      map.erase(*key);
    } else {
      auto newEnd = std::remove(vec.begin(), vec.end(), val);
      vec.resize(newEnd - vec.begin());
    }
  }
}
} // namespace

bool FileFormatManager::removeFormat(const std::string& identifier)
{
  FormatIdVector ids = m_identifiers[identifier];
  m_identifiers.erase(identifier);

  if (ids.empty())
    return false;

  for (size_t id : ids) {
    FileFormat* fmt = m_formats[id];

    if (fmt == nullptr)
      continue;

    removeFromMap(m_mimeTypes, fmt->mimeTypes(), id);
    removeFromMap(m_fileExtensions, fmt->fileExtensions(), id);

    m_formats[id] = nullptr;
    delete fmt;
  }

  return true;
}

FileFormat* FileFormatManager::newFormatFromIdentifier(
  const std::string& id, FileFormat::Operations filter) const
{
  FileFormat* format(filteredFormatFromFormatMap(id, filter, m_identifiers));
  return format ? format->newInstance() : nullptr;
}

FileFormat* FileFormatManager::newFormatFromMimeType(
  const std::string& mime, FileFormat::Operations filter) const
{
  FileFormat* format(filteredFormatFromFormatMap(mime, filter, m_mimeTypes));
  return format ? format->newInstance() : nullptr;
}

FileFormat* FileFormatManager::newFormatFromFileExtension(
  const std::string& extension, FileFormat::Operations filter) const
{
  FileFormat* format(
    filteredFormatFromFormatMap(extension, filter, m_fileExtensions));
  return format ? format->newInstance() : nullptr;
}

std::vector<std::string> FileFormatManager::identifiers(
  FileFormat::Operations filter) const
{
  return filteredKeysFromFormatMap(filter, m_identifiers);
}

std::vector<std::string> FileFormatManager::mimeTypes(
  FileFormat::Operations filter) const
{
  return filteredKeysFromFormatMap(filter, m_mimeTypes);
}

std::vector<std::string> FileFormatManager::fileExtensions(
  FileFormat::Operations filter) const
{
  return filteredKeysFromFormatMap(filter, m_fileExtensions);
}

std::vector<const FileFormat*> FileFormatManager::fileFormats(
  FileFormat::Operations filter) const
{
  std::vector<const FileFormat*> result;

  for (auto m_format : m_formats) {
    if (filter == FileFormat::None ||
        (filter & m_format->supportedOperations()) == filter) {
      result.push_back(m_format);
    }
  }
  return result;
}

std::vector<const FileFormat*> FileFormatManager::fileFormatsFromMimeType(
  const std::string& mimeType, FileFormat::Operations filter) const
{
  std::vector<FileFormat*> matches =
    filteredFormatsFromFormatMap(mimeType, filter, m_mimeTypes);

  return std::vector<const FileFormat*>(matches.begin(), matches.end());
}

std::vector<const FileFormat*> FileFormatManager::fileFormatsFromFileExtension(
  const std::string& extension, FileFormat::Operations filter) const
{
  std::vector<FileFormat*> matches =
    filteredFormatsFromFormatMap(extension, filter, m_fileExtensions);

  return std::vector<const FileFormat*>(matches.begin(), matches.end());
}

std::string FileFormatManager::error() const
{
  return m_error;
}

FileFormatManager::FileFormatManager()
{
  addFormat(new CmlFormat);
  addFormat(new CjsonFormat);
  addFormat(new DcdFormat);
  addFormat(new GromacsFormat);
  addFormat(new LammpsTrajectoryFormat);
  addFormat(new LammpsDataFormat);
  addFormat(new MdlFormat);
  addFormat(new OutcarFormat);
  addFormat(new PdbFormat);
  addFormat(new PoscarFormat);
  addFormat(new SdfFormat);
  // Write only, so the Open Babel plugin stays the reader for "smi": a SMILES
  // string carries no coordinates, and generating them is still its job.
  addFormat(new SmilesFormat);
  addFormat(new TrrFormat);
  addFormat(new TurbomoleFormat);
  addFormat(new XyzFormat);
#ifdef AVO_USE_MMTF
  addFormat(new MMTFFormat);
#endif
}

FileFormatManager::~FileFormatManager()
{
  // Delete the file formats that were loaded.
  for (auto& m_format : m_formats) {
    delete m_format;
  }
  m_formats.clear();
}

std::vector<std::string> FileFormatManager::filteredKeysFromFormatMap(
  FileFormat::Operations filter,
  const FileFormatManager::FormatIdMap& fmap) const
{
  std::vector<std::string> result;
  for (const auto& it : fmap) {
    for (auto formatIt = it.second.begin(); formatIt != it.second.end();
         ++formatIt) {
      if (filter == FileFormat::None ||
          (m_formats[*formatIt]->supportedOperations() & filter) == filter) {
        result.push_back(it.first);
        break;
      }
    }
  }
  return result;
}

std::vector<FileFormat*> FileFormatManager::filteredFormatsFromFormatMap(
  const std::string& key, FileFormat::Operations filter,
  const FileFormatManager::FormatIdMap& fmap) const
{
  std::vector<FileFormat*> result;

  auto it = fmap.find(key);
  if (it != fmap.end())
    result = filteredFormatsFromFormatVector(filter, it->second);

  return result;
}

FileFormat* FileFormatManager::filteredFormatFromFormatMap(
  const std::string& key, FileFormat::Operations filter,
  const FileFormatManager::FormatIdMap& fmap) const
{
  auto it = fmap.find(key);
  if (it != fmap.end())
    return filteredFormatFromFormatVector(filter, it->second);

  return nullptr;
}

std::vector<FileFormat*> FileFormatManager::filteredFormatsFromFormatVector(
  FileFormat::Operations filter,
  const FileFormatManager::FormatIdVector& v) const
{
  std::vector<FileFormat*> result;
  for (unsigned long it : v) {
    if (filter == FileFormat::None ||
        (m_formats[it]->supportedOperations() & filter) == filter) {
      result.push_back(m_formats[it]);
    }
  }
  return result;
}

FileFormat* FileFormatManager::filteredFormatFromFormatVector(
  FileFormat::Operations filter,
  const FileFormatManager::FormatIdVector& v) const
{
  for (unsigned long it : v) {
    if (filter == FileFormat::None ||
        (m_formats[it]->supportedOperations() & filter) == filter) {
      return m_formats[it];
    }
  }
  return nullptr;
}

void FileFormatManager::appendError(const std::string& errorMessage) const
{
  m_error += errorMessage + "\n";
}

} // namespace Avogadro::Io
