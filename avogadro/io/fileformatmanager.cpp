/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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
#include "turbomoleformat.h"
#include "vaspformat.h"
#include "xyzformat.h"

#ifdef AVO_USE_MMTF
#include "mmtfformat.h"
#endif

#include <algorithm>
#include <memory>

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
  for (auto & m_format : m_formats) {
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
  for (auto & mime : mimes) {
    m_mimeTypes[mime].push_back(index);
  }
  std::vector<std::string> extensions = format->fileExtensions();
  for (auto & extension : extensions) {
    m_fileExtensions[extension].push_back(index);
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
  for (auto key = keys.begin(), keyEnd = keys.end(); key != keyEnd; ++key) {
    auto mapMatch = map.find(*key);
    if (mapMatch == map.end())
      continue;
    typename Map::mapped_type& vec = mapMatch->second;
    if (vec.size() <= 1) {
      map.erase(*key);
    } else {
      auto newEnd =
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
  for (auto & m_format : m_formats) {
    delete m_format;
  }
  m_formats.clear();
}

std::vector<std::string> FileFormatManager::filteredKeysFromFormatMap(
  FileFormat::Operations filter,
  const FileFormatManager::FormatIdMap& fmap) const
{
  std::vector<std::string> result;
  for (const auto & it : fmap) {
    for (auto formatIt = it.second.begin();
         formatIt != it.second.end(); ++formatIt) {
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

void FileFormatManager::appendError(const std::string& errorMessage)
{
  m_error += errorMessage + "\n";
}

} // end Avogadro namespace
