/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "fileformat.h"

#include <fstream>
#include <locale>
#include <sstream>

namespace Avogadro {
namespace Io {

using std::ifstream;
using std::locale;
using std::ofstream;

FileFormat::FileFormat(const std::string &fileName_, Operation mode_)
  : m_fileName(fileName_), m_mode(mode_), m_in(NULL), m_out(NULL)
{
  if (!m_fileName.empty()) {
    if (m_mode == Read)
      m_in = new ifstream(m_fileName.c_str(), std::ifstream::binary);
    else if (m_mode == Write)
      m_out = new ofstream(m_fileName.c_str(), std::ofstream::binary);
  }
}

FileFormat::~FileFormat()
{
  delete m_in;
  delete m_out;
}

bool FileFormat::readMolecule(Core::Molecule &molecule)
{
  if (!m_in)
    return false;
  return read(*m_in, molecule);
}

bool FileFormat::readFile(const std::string &fileName_,
                          Core::Molecule &molecule)
{
  m_fileName = fileName_;
  std::ifstream file(fileName_.c_str(), std::ifstream::binary);
  if (!file.is_open()) {
    appendError("Error opening file: " + fileName_ + "\n");
    return false;
  }
  // Imbue the standard C locale.
  locale cLocale("C");
  file.imbue(cLocale);
  return read(file, molecule);
}

bool FileFormat::writeFile(const std::string &fileName_,
                           const Core::Molecule &molecule)
{
  m_fileName = fileName_;
  std::ofstream file(fileName_.c_str(), std::ofstream::binary);
  if (!file.is_open()) {
    appendError("Error opening file: " + fileName_ + "\n");
    return false;
  }
  // Imbue the standard C locale.
  locale cLocale("C");
  file.imbue(cLocale);
  return write(file, molecule);
}

bool FileFormat::readString(const std::string &string, Core::Molecule &molecule)
{
  std::istringstream stream(string, std::istringstream::in);
  // Imbue the standard C locale.
  locale cLocale("C");
  stream.imbue(cLocale);
  return read(stream, molecule);
}

bool FileFormat::writeString(std::string &string,
                             const Core::Molecule &molecule)
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

void FileFormat::appendError(const std::string &errorString, bool newLine)
{
  m_error += errorString;
  if (newLine)
    m_error += "\n";
}

} // namespace Io
} // namespace Avogadro
