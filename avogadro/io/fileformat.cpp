/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "fileformat.h"

#include <algorithm>
#include <fstream>
#include <locale>
#include <sstream>

namespace Avogadro::Io {

using std::ifstream;
using std::locale;
using std::ofstream;

FileFormat::FileFormat() : m_mode(None), m_in(nullptr), m_out(nullptr) {}

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
  m_fileName = fileName_;
  m_mode = mode_;
  if (!m_fileName.empty()) {
    // Imbue the standard C locale.
    locale cLocale("C");
    if (m_mode & Read) {
      auto* file = new ifstream(m_fileName.c_str(), std::ifstream::binary);
      m_in = file;
      if (file->is_open()) {
        m_in->imbue(cLocale);
        return true;
      } else {
        appendError("Error opening file: " + fileName_);
        return false;
      }
    } else if (m_mode & Write) {
      auto* file = new ofstream(m_fileName.c_str(), std::ofstream::binary);
      m_out = file;
      if (file->is_open()) {
        m_out->imbue(cLocale);
        return true;
      } else {
        appendError("Error opening file: " + fileName_);
        return false;
      }
    }
  }
  return false;
}

void FileFormat::close()
{
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
  return read(*m_in, molecule);
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
  return result;
}

bool FileFormat::readString(const std::string& string, Core::Molecule& molecule)
{
  std::istringstream stream(string, std::istringstream::in);
  // Imbue the standard C locale.
  locale cLocale("C");
  stream.imbue(cLocale);
  return read(stream, molecule);
}

bool FileFormat::writeString(std::string& string,
                             const Core::Molecule& molecule)
{
  std::ostringstream stream(string, std::ostringstream::out);
  // Imbue the standard C locale.
  locale cLocale("C");
  stream.imbue(cLocale);
  bool result = write(stream, molecule);
  string = stream.str();
  return result;
}

void FileFormat::clear()
{
  m_fileName.clear();
  m_error.clear();
}

void FileFormat::appendError(const std::string& errorString, bool newLine)
{
  m_error += errorString;
  if (newLine)
    m_error += "\n";
}

} // namespace Avogadro::Io
