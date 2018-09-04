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

#include "cjsonformat.h"
#include "cmlformat.h"
#include "dcdformat.h"
#include "gromacsformat.h"
#include "lammpsformat.h"
#include "mdlformat.h"
#include "pdbformat.h"
#include "trrformat.h"
#include "vaspformat.h"
#include "xyzformat.h"

#ifdef AVO_USE_MMTF
#include "mmtfformat.h"
#endif

#include <algorithm>
#include <memory>

using std::unique_ptr;

namespace Avogadro {
namespace Io {

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
  FileFormat* format(nullptr);
  if (fileExtension.empty()) {
    // We need to guess the file extension.
    size_t pos = fileName.find_last_of('.');
    format = filteredFormatFromFormatMap(fileName.substr(pos + 1),
                                         FileFormat::Read | FileFormat::File,
                                         m_fileExtensions);
  } else {
    format = filteredFormatFromFormatMap(
      fileExtension, FileFormat::Read | FileFormat::File, m_fileExtensions);
  }
  if (!format)
    return false;

  unique_ptr<FileFormat> formatInstance(format->newInstance());
  formatInstance->setOptions(options);
  return formatInstance->readFile(fileName, molecule);
}

bool FileFormatManager::writeFile(const Core::Molecule& molecule,
                                  const std::string& fileName,
                                  const std::string& fileExtension,
                                  const std::string& options) const
{
  FileFormat* format(nullptr);
  if (fileExtension.empty()) {
    // We need to guess the file extension.
    size_t pos = fileName.find_last_of('.');
    format = filteredFormatFromFormatMap(fileName.substr(pos + 1),
                                         FileFormat::Write | FileFormat::File,
                                         m_fileExtensions);
  } else {
    format = filteredFormatFromFormatMap(
      fileExtension, FileFormat::Write | FileFormat::File, m_fileExtensions);
  }
  if (!format)
    return false;

  unique_ptr<FileFormat> formatInstance(format->newInstance());
  formatInstance->setOptions(options);
  return formatInstance->writeFile(fileName, molecule);
}

bool FileFormatManager::readString(Core::Molecule& molecule,
                                   const std::string& string,
                                   const std::string& fileExtension,
                                   const std::string& options) const
{
  FileFormat* format(filteredFormatFromFormatMap(
    fileExtension, FileFormat::Read | FileFormat::String, m_fileExtensions));
  if (!format)
    return false;

  unique_ptr<FileFormat> formatInstance(format->newInstance());
  formatInstance->setOptions(options);
  return formatInstance->readString(string, molecule);
}

bool FileFormatManager::writeString(const Core::Molecule& molecule,
                                    std::string& string,
                                    const std::string& fileExtension,
                                    const std::string& options) const
{
  FileFormat* format(filteredFormatFromFormatMap(
    fileExtension, FileFormat::Write | FileFormat::String, m_fileExtensions));
  if (!format)
    return false;

  unique_ptr<FileFormat> formatInstance(format->newInstance());
  formatInstance->setOptions(options);
  return formatInstance->writeString(string, molecule);
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
  for (std::vector<FileFormat*>::const_iterator it = m_formats.begin();
       it != m_formats.end(); ++it) {
    if (*it == format) {
      appendError("The format object was already loaded.");
      return false;
    }
  }

  // If we got here then the format is unique enough to be added.
  size_t index = m_formats.size();
  m_formats.push_back(format);
  m_identifiers[format->identifier()].push_back(index);
  std::vector<std::string> mimes = format->mimeTypes();
  for (std::vector<std::string>::const_iterator it = mimes.begin();
       it != mimes.end(); ++it) {
    m_mimeTypes[*it].push_back(index);
  }
  std::vector<std::string> extensions = format->fileExtensions();
  for (std::vector<std::string>::const_iterator it = extensions.begin();
       it != extensions.end(); ++it) {
    m_fileExtensions[*it].push_back(index);
  }

  return true;
}

namespace {
// Lookup each key from "keys" in "map", and remove "val" from the Map's
// data value (which is a vector of ValueType)
template<typename Map, typename VectorOfKeys, typename ValueType>
void removeFromMap(Map& map, const VectorOfKeys& keys, const ValueType& val)
{
  typedef typename VectorOfKeys::const_iterator KeysIter;
  for (KeysIter key = keys.begin(), keyEnd = keys.end(); key != keyEnd; ++key) {
    typename Map::iterator mapMatch = map.find(*key);
    if (mapMatch == map.end())
      continue;
    typename Map::mapped_type& vec = mapMatch->second;
    if (vec.size() <= 1) {
      map.erase(*key);
    } else {
      typename Map::mapped_type::iterator newEnd =
        std::remove(vec.begin(), vec.end(), val);
      vec.resize(newEnd - vec.begin());
    }
  }
}
}

bool FileFormatManager::removeFormat(const std::string& identifier)
{
  FormatIdVector ids = m_identifiers[identifier];
  m_identifiers.erase(identifier);

  if (ids.empty())
    return false;

  for (FormatIdVector::const_iterator it = ids.begin(), itEnd = ids.end();
       it != itEnd; ++it) {
    FileFormat* fmt = m_formats[*it];

    if (fmt == nullptr)
      continue;

    removeFromMap(m_mimeTypes, fmt->mimeTypes(), *it);
    removeFromMap(m_fileExtensions, fmt->fileExtensions(), *it);

    m_formats[*it] = nullptr;
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

  for (std::vector<FileFormat*>::const_iterator it = m_formats.begin(),
                                                itEnd = m_formats.end();
       it != itEnd; ++it) {
    if (filter == FileFormat::None ||
        (filter & (*it)->supportedOperations()) == filter) {
      result.push_back(*it);
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
  addFormat(new GromacsFormat);
  addFormat(new MdlFormat);
  addFormat(new OutcarFormat);
  addFormat(new PdbFormat);
  addFormat(new PoscarFormat);
  addFormat(new TrrFormat);
  addFormat(new XyzFormat);
  addFormat(new DcdFormat);
  addFormat(new LammpsTrajectoryFormat);
  addFormat(new LammpsDataFormat);
#ifdef AVO_USE_MMTF
  addFormat(new MMTFFormat);
#endif
}

FileFormatManager::~FileFormatManager()
{
  // Delete the file formats that were loaded.
  for (std::vector<FileFormat*>::const_iterator it = m_formats.begin();
       it != m_formats.end(); ++it) {
    delete (*it);
  }
  m_formats.clear();
}

std::vector<std::string> FileFormatManager::filteredKeysFromFormatMap(
  FileFormat::Operations filter,
  const FileFormatManager::FormatIdMap& fmap) const
{
  std::vector<std::string> result;
  for (FormatIdMap::const_iterator it = fmap.begin(); it != fmap.end(); ++it) {
    for (std::vector<size_t>::const_iterator formatIt = it->second.begin();
         formatIt != it->second.end(); ++formatIt) {
      if (filter == FileFormat::None ||
          (m_formats[*formatIt]->supportedOperations() & filter) == filter) {
        result.push_back(it->first);
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

  FormatIdMap::const_iterator it = fmap.find(key);
  if (it != fmap.end())
    result = filteredFormatsFromFormatVector(filter, it->second);

  return result;
}

FileFormat* FileFormatManager::filteredFormatFromFormatMap(
  const std::string& key, FileFormat::Operations filter,
  const FileFormatManager::FormatIdMap& fmap) const
{
  FormatIdMap::const_iterator it = fmap.find(key);
  if (it != fmap.end())
    return filteredFormatFromFormatVector(filter, it->second);

  return nullptr;
}

std::vector<FileFormat*> FileFormatManager::filteredFormatsFromFormatVector(
  FileFormat::Operations filter,
  const FileFormatManager::FormatIdVector& v) const
{
  std::vector<FileFormat*> result;
  for (FormatIdVector::const_iterator it = v.begin(); it != v.end(); ++it) {
    if (filter == FileFormat::None ||
        (m_formats[*it]->supportedOperations() & filter) == filter) {
      result.push_back(m_formats[*it]);
    }
  }
  return result;
}

FileFormat* FileFormatManager::filteredFormatFromFormatVector(
  FileFormat::Operations filter,
  const FileFormatManager::FormatIdVector& v) const
{
  for (FormatIdVector::const_iterator it = v.begin(); it != v.end(); ++it) {
    if (filter == FileFormat::None ||
        (m_formats[*it]->supportedOperations() & filter) == filter) {
      return m_formats[*it];
    }
  }
  return nullptr;
}

void FileFormatManager::appendError(const std::string& errorMessage)
{
  m_error += errorMessage + "\n";
}

} // end Io namespace
} // end Avogadro namespace
