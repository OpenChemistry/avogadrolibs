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

#include "fileformatmanager.h"

#include "fileformat.h"

#include "cmlformat.h"
#include "cjsonformat.h"

#include <iostream>

namespace Avogadro {
namespace Io {

// Class to ensure the FileFormatManager singleton's destructor is called before
// the program exits. You must set the singleton on the class for this to
// happen. If the singleton is never instanced then nothing happens.
class FileFormatManager::Destroyer
{
public:
  Destroyer() : m_singleton(0) { }
  ~Destroyer() { delete m_singleton; }
  void setSingleton(FileFormatManager *s) { m_singleton = s; }
private:
  FileFormatManager* m_singleton;
};

FileFormatManager* FileFormatManager::m_instance;
FileFormatManager::Destroyer FileFormatManager::m_destroyer;

FileFormatManager& FileFormatManager::instance()
{
  // FIXME: We should probably add mutexes here for thread safety.
  if (!m_instance) {
    m_instance = new FileFormatManager;
    m_destroyer.setSingleton(m_instance);
    m_instance->addFormat(new CmlFormat);
    m_instance->addFormat(new CjsonFormat);
  }

  return *m_instance;
}

bool FileFormatManager::readFile(Core::Molecule &molecule,
                                 const std::string &fileName,
                                 const std::string &fileExtension)
{
  FileFormat *format(NULL);
  if (fileExtension.empty()) {
    // We need to guess the file extension.
    size_t pos = fileName.find_last_of('.');
    std::cout << fileName.substr(pos + 1) << " suffix found." << std::endl;
    format = formatFromFileExtension(fileName.substr(pos + 1));
  }
  else {
    format = formatFromFileExtension(fileExtension);
  }
  if (!format)
    return false;

  return format->readFile(fileName, molecule);
}

bool FileFormatManager::writeFile(Core::Molecule &molecule,
                                  const std::string &fileName,
                                  const std::string &fileExtension)
{
  FileFormat *format(NULL);
  if (fileExtension.empty()) {
    // We need to guess the file extension.
    size_t pos = fileName.find_last_of('.');
    format = formatFromFileExtension(fileName.substr(pos + 1));
  }
  else {
    format = formatFromFileExtension(fileExtension);
  }
  if (!format)
    return false;

  return format->writeFile(fileName, molecule);
}

bool FileFormatManager::readString(Core::Molecule &molecule,
                                   const std::string &string,
                                   const std::string &fileExtension)
{
  FileFormat *format(formatFromFileExtension(fileExtension));
  if (!format)
    return false;

  return format->readString(string, molecule);
}

bool FileFormatManager::writeString(Core::Molecule &molecule,
                                    std::string &string,
                                    const std::string &fileExtension)
{
  FileFormat *format(formatFromFileExtension(fileExtension));
  if (!format)
    return false;

  return format->writeString(string, molecule);
}

bool FileFormatManager::registerFormat(FileFormat *format)
{
  return instance().addFormat(format);
}

bool FileFormatManager::addFormat(FileFormat *format)
{
  if (!format) {
    appendError("Supplied format was null.");
    return false;
  }
  if (m_identifiers.count(format->identifier()) > 0) {
    appendError("Format " + format->identifier() + " already loaded.");
    return false;
  }
  for (std::vector<FileFormat *>::const_iterator it = m_formats.begin();
       it != m_formats.end(); ++it) {
    if (*it == format) {
      appendError("The format object was already loaded.");
      return false;
    }
  }

  // If we got here then the format is unique enough to be added.
  size_t index = m_formats.size();
  m_formats.push_back(format);
  m_identifiers[format->identifier()] = index;
  std::vector<std::string> mimes = format->mimeTypes();
  for (std::vector<std::string>::const_iterator it = mimes.begin();
       it != mimes.end(); ++it) {
    m_mimeTypes[*it] = index;
  }
  std::vector<std::string> extensions = format->fileExtensions();
  for (std::vector<std::string>::const_iterator it = extensions.begin();
       it != extensions.end(); ++it) {
    m_fileExtensions.insert(std::pair<std::string, size_t>(*it, index));
  }

  return true;
}

FileFormat * FileFormatManager::newFormatFromIdentifier(const std::string &id)
{
  FileFormat *format(formatFromIdentifier(id));
  return format ? format->createInstance() : NULL;
}

FileFormat * FileFormatManager::newFormatFromMimeType(const std::string &mime)
{
  FileFormat *format(formatFromMimeType(mime));
  return format ? format->createInstance() : NULL;
}

FileFormat * FileFormatManager::newFormatFromFileExtension(
  const std::string &extension)
{
  FileFormat *format(formatFromFileExtension(extension));
  return format ? format->createInstance() : NULL;
}

std::vector<std::string> FileFormatManager::identifiers() const
{
  std::vector<std::string> ids;
  for (std::map<std::string, size_t>::const_iterator it = m_identifiers.begin();
       it != m_identifiers.end(); ++it) {
    ids.push_back(it->first);
  }
  return ids;
}

std::vector<std::string> FileFormatManager::mimeTypes() const
{
  std::vector<std::string> mimes;
  for (std::map<std::string, size_t>::const_iterator it = m_mimeTypes.begin();
       it != m_mimeTypes.end(); ++it) {
    mimes.push_back(it->first);
  }
  return mimes;
}

std::vector<std::string> FileFormatManager::fileExtensions() const
{
  std::vector<std::string> extensions;
  for (std::multimap<std::string, size_t>::const_iterator it
       = m_fileExtensions.begin(); it != m_fileExtensions.end(); ++it) {
    extensions.push_back(it->first);
  }
  return extensions;
}

std::string FileFormatManager::error() const
{
  return m_error;
}

FileFormatManager::FileFormatManager()
{
}

FileFormatManager::~FileFormatManager()
{
  // Delete the file formats that were loaded.
  for (std::vector<FileFormat *>::const_iterator it = m_formats.begin();
       it != m_formats.end(); ++it) {
    delete (*it);
  }
  m_formats.clear();
}

FileFormat * FileFormatManager::formatFromIdentifier(const std::string &id)
{
   std::map<std::string, size_t>::const_iterator it = m_identifiers.find(id);
   return it == m_identifiers.end() ? NULL : m_formats[it->second];
}

FileFormat * FileFormatManager::formatFromMimeType(const std::string &mime)
{
  std::map<std::string, size_t>::const_iterator it = m_mimeTypes.find(mime);
  return it == m_mimeTypes.end() ? NULL : m_formats[it->second];
}

FileFormat * FileFormatManager::formatFromFileExtension(
  const std::string &extension)
{
  std::multimap<std::string, size_t>::const_iterator it =
    m_fileExtensions.find(extension);
  return it == m_fileExtensions.end() ? NULL : m_formats[it->second];
}

void FileFormatManager::appendError(const std::string &errorMessage)
{
  m_error += errorMessage + "\n";
}

} // end Io namespace
} // end Avogadro namespace
