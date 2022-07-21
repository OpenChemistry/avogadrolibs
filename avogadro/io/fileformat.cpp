/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "fileformat.h"

#include <fstream>
#include <locale>
#include <sstream>

namespace Avogadro::Io {

using std::ifstream;
using std::locale;
using std::ofstream;

FileFormat::FileFormat() : m_mode(None), m_in(nullptr), m_out(nullptr)
{
}

FileFormat::~FileFormat()
{
  delete m_in;
  delete m_out;
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

} // namespace Avogadro
