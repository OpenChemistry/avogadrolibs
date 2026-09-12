/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_FILEFORMATMANAGER_H
#define AVOGADRO_IO_FILEFORMATMANAGER_H

#include "avogadroioexport.h"

#include "fileformat.h" // For FileFormat::Operation enum.

#include <map>
#include <string>
#include <vector>

namespace Avogadro {
namespace Core {
class Molecule;
}
namespace Io {

/**
 * @struct CaseInsensitiveComparator fileformatmanager.h
 * <avogadro/io/fileformatmanager.h>
 * @brief Class to handle case-insensitive comparisons of file extensions.
 * Adapted from https://stackoverflow.com/a/3009806/131896
 **/
struct CaseInsensitiveComparator
{
  // case-independent (ci) compare_less binary function
  struct lowerCaseCompare
  {
    bool operator()(const unsigned char& c1, const unsigned char& c2) const
    {
      return tolower(c1) < tolower(c2);
    }
  };
  bool operator()(const std::string& s1, const std::string& s2) const noexcept
  {
    return std::lexicographical_compare(s1.begin(), s1.end(), // source range
                                        s2.begin(), s2.end(), // dest range
                                        lowerCaseCompare());  // comparison
  }
};

/**
 * @class FileFormatManager fileformatmanager.h
 * <avogadro/io/fileformatmanager.h>
 * @brief Class to manage registration, searching and creation of file formats.
 * @author Marcus D. Hanwell
 *
 * The file format manager is a singleton class that handles the runtime
 * registration, search, creation and eventual destruction of file formats. It
 * can be used to gain a listing of available formats, register new formats and
 * retrieve the correct format to facilitate file IO.
 *
 * All files IO can take place independent of this manager, but for automated
 * registration and look up this is the preferred API. It is possible to use
 * the convenience API without ever dealing directly with a format class.
 */

class AVOGADROIO_EXPORT FileFormatManager
{
public:
  /**
   * Get the singleton instance of the file format manager. This instance should
   * not be deleted.
   */
  static FileFormatManager& instance();

  /**
   * Load @p molecule with the @p fileName contents supplied, inferring the
   * @p fileExtension if it is empty. The @p options can be used to modify
   * the behavior of the file format.
   *
   * A compressed file (.gz, .bz2, .xz, .zst) is handled transparently: the
   * codec is detected from the file's content, not its name, so even a
   * misnamed compressed file is decoded correctly. The format to use is
   * chosen from @p fileName (or @p fileExtension) with any compression
   * suffix removed, e.g. "molecule.xyz.gz" is read as XYZ.
   * @return True on success, false on failure.
   */
  bool readFile(Core::Molecule& molecule, const std::string& fileName,
                const std::string& fileExtension = std::string(),
                const std::string& options = std::string()) const;

  /**
   * Write @p molecule to the @p fileName supplied, inferring the
   * @p fileExtension if it is empty. The @p options can be used to modify
   * the behavior of the file format.
   *
   * A compressed file (.gz, .bz2, .xz, .zst) is handled transparently: the
   * codec is chosen from @p fileName's extension (e.g. "molecule.xyz.gz"
   * writes gzip-compressed XYZ), and the format to use is chosen from the
   * name with that compression suffix removed.
   * @return True on success, false on failure.
   */
  bool writeFile(const Core::Molecule& molecule, const std::string& fileName,
                 const std::string& fileExtension = std::string(),
                 const std::string& options = std::string()) const;

  /**
   * Load @p molecule with the contents of @p string, using the supplied
   * @p fileExtension to determine the format. The @p options can be used to
   * modify the behavior of the file format.
   *
   * Compressed content is handled transparently: the codec is detected from
   * @p string's own content, not from @p fileExtension, so @p string may hold
   * compressed bytes even though @p fileExtension names the chemical format
   * only (e.g. "xyz").
   * @return True on success, false on failure.
   */
  bool readString(Core::Molecule& molecule, const std::string& string,
                  const std::string& fileExtension,
                  const std::string& options = std::string()) const;

  /**
   * Write @p molecule to the @p string, using the supplied @p fileExtension
   * to determine the format. The @p options can be used to modify the behavior
   * of the file format.
   *
   * A compression suffix on @p fileExtension (e.g. "cjson.gz") is honored:
   * the format is chosen from the extension with that suffix removed, and
   * @p string is filled with the compressed bytes.
   * @return True on success, false on failure.
   */
  bool writeString(const Core::Molecule& molecule, std::string& string,
                   const std::string& fileExtension,
                   const std::string& options = std::string()) const;

  /**
   * @brief Register a new file format with the format manager.
   * @param format An instance of the format to manage, the manager assumes
   * ownership of the object passed in.
   * @return True on success, false on failure.
   */
  static bool registerFormat(FileFormat* format);

  /**
   * @brief Unregister a file format from the format manager.
   * @param identifier The identifier for the format to remove.
   * @return True on success, false on failure.
   */
  static bool unregisterFormat(const std::string& identifier);

  /**
   * Add the supplied @p format to the manager, registering its ID, MIME type,
   * file extension and other relevant data for later lookup. The manager
   * assumes ownership of the supplied object.
   * @return True on success, false on failure.
   */
  bool addFormat(FileFormat* format);

  /**
   * Remove the format with the identifier @a identifier from the manager.
   * @return True on success, false on failure.
   */
  bool removeFormat(const std::string& identifier);

  /**
   * New instance of the format for the specified @p identifier. Ownership
   * is passed to the caller.
   * @param identifier The unique identifier of the format.
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   * @return Instance of the format, nullptr if not found. Ownership passes to
   * the
   * caller.
   */
  FileFormat* newFormatFromIdentifier(
    const std::string& identifier,
    FileFormat::Operations filter = FileFormat::None) const;

  /**
   * New instance of the format for the specified @p mimeType. Ownership
   * is passed to the caller.
   * @param mimeType The MIME type (in lower case).
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   * @return Instance of the format, nullptr if not found. Ownership passes to
   * the
   * caller.
   */
  FileFormat* newFormatFromMimeType(
    const std::string& mimeType,
    FileFormat::Operations filter = FileFormat::None) const;

  /**
   * New instance of the format for the specified file @p extension. Ownership
   * is passed to the caller.
   * @param extension The file extension (in lower case).
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   * @return Instance of the format, nullptr if not found. Ownership passes to
   * the
   * caller.
   */
  FileFormat* newFormatFromFileExtension(
    const std::string& extension,
    FileFormat::Operations filter = FileFormat::None) const;

  /**
   * Get a list of all loaded identifiers, optionally matching the specified
   * filter.
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   */
  std::vector<std::string> identifiers(
    FileFormat::Operations filter = FileFormat::None) const;

  /**
   * Get a list of all loaded MIME types, optionally matching the specified
   * filter.
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   */
  std::vector<std::string> mimeTypes(
    FileFormat::Operations filter = FileFormat::None) const;

  /**
   * Get a list of the file extensions supported, optionally matching the
   * specified filter.
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   */
  std::vector<std::string> fileExtensions(
    FileFormat::Operations filter = FileFormat::None) const;

  /**
   * Get a list of known FileFormat objects, optionally matching the
   * specified filter.
   * @warning The objects in the returned list are owned by the
   * FileFormatManager and cannot be modified. Use FileFormat::newInstance()
   * to create mutable copies.
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   */
  std::vector<const FileFormat*> fileFormats(
    FileFormat::Operations filter = FileFormat::None) const;

  /**
   * Get a list of known FileFormat objects that handle the specified MIME type,
   * optionally matching a filter.
   * @warning The objects in the returned list are owned by the
   * FileFormatManager and cannot be modified. Use FileFormat::newInstance()
   * to create mutable copies.
   * @param mimeType MIME type.
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   */
  std::vector<const FileFormat*> fileFormatsFromMimeType(
    const std::string& mimeType,
    FileFormat::Operations filter = FileFormat::None) const;

  /**
   * Get a list of known FileFormat objects that handle the specified file
   * extension, optionally matching a filter.
   * @warning The objects in the returned list are owned by the
   * FileFormatManager and cannot be modified. Use FileFormat::newInstance()
   * to create mutable copies.
   * @param extension File extension.
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   */
  std::vector<const FileFormat*> fileFormatsFromFileExtension(
    const std::string& extension,
    FileFormat::Operations filter = FileFormat::None) const;

  /**
   * Get any errors that have been logged when loading formats.
   */
  std::string error() const;

private:
  using FormatIdVector = std::vector<size_t>;
  using FormatIdMap =
    std::map<std::string, FormatIdVector, CaseInsensitiveComparator>;

  FileFormatManager();
  ~FileFormatManager();

  FileFormatManager(const FileFormatManager&);            // Not implemented.
  FileFormatManager& operator=(const FileFormatManager&); // Not implemented.

  /**
   * @brief Return keys from a map that have formats matching the supplied
   * operation filter.
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   * @param fmap The FormatMap to operate on.
   */
  std::vector<std::string> filteredKeysFromFormatMap(
    FileFormat::Operations filter, const FormatIdMap& fmap) const;

  /**
   * @brief Return formats from a map that match the supplied key and operation
   * filter.
   * @note Ownership of the format filter(s) remains with the FileFormatManager.
   * Use FileFormat::newInstance to clone each format before use.
   * @param key The map key.
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   * @param fmap The FormatIdMap to operate on.
   */
  std::vector<FileFormat*> filteredFormatsFromFormatMap(
    const std::string& key, FileFormat::Operations filter,
    const FormatIdMap& fmap) const;

  /**
   * @brief Return a format from a map that matches the supplied key and
   * operation filter.
   * @note Ownership of the format filter(s) remains with the FileFormatManager.
   * Use FileFormat::newInstance to clone each format before use.
   * @param key The map key.
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   * @param fmap The FormatIdMap to operate on.
   */
  FileFormat* filteredFormatFromFormatMap(const std::string& key,
                                          FileFormat::Operations filter,
                                          const FormatIdMap& fmap) const;

  /**
   * @brief Return formats from a vector that match the supplied operation
   * filter.
   * @note Ownership of the format filter(s) remains with the FileFormatManager.
   * Use FileFormat::newInstance to clone each format before use.
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   * @param fvec The FormatIdVector to operate on.
   */
  std::vector<FileFormat*> filteredFormatsFromFormatVector(
    FileFormat::Operations filter, const FormatIdVector& fvec) const;

  /**
   * @brief Return the first format from a vector that matches the supplied
   * operation filter.
   * @note Ownership of the format filter(s) remains with the FileFormatManager.
   * Use FileFormat::newInstance to clone each format before use.
   * @param filter Bitwise combination of FileFormat::Operation values that
   * represents the minimum required capabilities.
   * @param fvec The FormatIdVector to operate on.
   */
  FileFormat* filteredFormatFromFormatVector(FileFormat::Operations filter,
                                             const FormatIdVector& fvec) const;

  /**
   * @brief Append warnings/errors to the calling thread's error message.
   *
   * The manager is a singleton every caller shares, and reads legitimately
   * happen on worker threads, so the message is kept per thread rather than in
   * one shared string that concurrent operations would race on and overwrite.
   * @param errorMessage The error message to append.
   */
  void appendError(const std::string& errorMessage) const;

  /**
   * @brief The extension to look a format up by.
   *
   * Prefers @p fileExtension when the caller supplied one, otherwise takes it
   * from @p fileName. Either way a compression suffix is removed first, so
   * that "molecule.xyz.gz" and an explicit "xyz.gz" both resolve by the
   * chemical extension "xyz" rather than by the codec's.
   */
  static std::string lookupExtension(const std::string& fileName,
                                     const std::string& fileExtension);

  std::vector<FileFormat*> m_formats;

  FormatIdMap m_identifiers;
  FormatIdMap m_mimeTypes;
  FormatIdMap m_fileExtensions;
};

} // namespace Io
} // namespace Avogadro

#endif // AVOGADRO_IO_FILEFORMATMANAGER_H
