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

#ifndef AVOGADRO_IO_FILEFORMATMANAGER_H
#define AVOGADRO_IO_FILEFORMATMANAGER_H

#include "avogadroioexport.h"

#include <vector>
#include <map>
#include <string>

namespace Avogadro {
namespace Core {
class Molecule;
}
namespace Io {

class FileFormat;

/**
 * @class FileFormatManager fileformatmanager.h <avogadro/io/fileformatmanager.h>
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
  static FileFormatManager & instance();

  /**
   * Load @p molecule with the @p fileName contents supplied, inferring the
   * @p fileExtension if it is empty.
   * @return True on success, false on failure.
   */
  bool readFile(Core::Molecule &molecule, const std::string &fileName,
                const std::string &fileExtension = std::string());

  /**
   * Write @p molecule to the @p fileName supplied, inferring the
   * @p fileExtension if it is empty.
   * @return True on success, false on failure.
   */
  bool writeFile(const Core::Molecule &molecule, const std::string &fileName,
                 const std::string &fileExtension = std::string());

  /**
   * Load @p molecule with the contents of @p string, using the supplied
   * @p fileExtension to determine the format.
   * @return True on success, false on failure.
   */
  bool readString(Core::Molecule &molecule, const std::string &string,
                  const std::string &fileExtension);

  /**
   * Write @p molecule to the @p string, using the supplied @p fileExtension
   * to determine the format.
   * @return True on success, false on failure.
   */
  bool writeString(const Core::Molecule &molecule, std::string &string,
                   const std::string &fileExtension);

  /**
   * @brief Register a new file format with the format manager.
   * @param format An instance of the format to manage, the manager assumes
   * ownership of the object passed in.
   * @return True on success, false on failure.
   */
  static bool registerFormat(FileFormat *format);

  /**
   * Add the supplied @p format to the manager, registering its ID, MIME type,
   * file extension and other relevant data for later lookup. The manager
   * assumes ownership of the supplied object.
   * @return True on success, false on failure.
   */
  bool addFormat(FileFormat *format);

  /**
   * New instance of the format for the specified @p identifier. Ownership
   * is passed to the caller.
   * @param identifier The unique identifier of the format.
   * @return Instance of the format, NULL if not found. Ownership passes to the
   * caller.
   */
  FileFormat * newFormatFromIdentifier(const std::string &identifier);

  /**
   * New instance of the format for the specified @p mimeType. Ownership
   * is passed to the caller.
   * @param mimeType The MIME type (in lower case).
   * @return Instance of the format, NULL if not found. Ownership passes to the
   * caller.
   */
  FileFormat * newFormatFromMimeType(const std::string &mimeType);

  /**
   * New instance of the format for the specified file @p extention. Ownership
   * is passed to the caller.
   * @param extension The file extension (in lower case).
   * @return Instance of the format, NULL if not found. Ownership passes to the
   * caller.
   */
  FileFormat * newFormatFromFileExtension(const std::string &extension);

  /**
   * Get a list of all loaded identifiers.
   */
  std::vector<std::string> identifiers() const;

  /**
   * Get a list of all loaded MIME types.
   */
  std::vector<std::string> mimeTypes() const;

  /**
   * Get a list of the file extensions supported.
   */
  std::vector<std::string> fileExtensions() const;

  /**
   * Get any errors that have been logged when loading formats.
   */
  std::string error() const;

private:
  FileFormatManager();
  ~FileFormatManager();

  FileFormatManager(const FileFormatManager&);            // Not implemented.
  FileFormatManager& operator=(const FileFormatManager&); // Not implemented.

  /**
   * Get a pointer to the format for the specified @p identifier. Ownership
   * remains with the manager class.
   */
  FileFormat * formatFromIdentifier(const std::string &identifier);

  /**
   * Get the format from the MIME type.
   * @param The MIME type (in lower case).
   * @return The format (ownership stays with manager) or NULL if not found.
   */
  FileFormat * formatFromMimeType(const std::string &mimeType);

  /**
   * Get the format from the file extension.
   * @param The file extension (in lower case).
   * @return The format (ownership stays with manager) or NULL if not found.
   */
  FileFormat * formatFromFileExtension(const std::string &extension);

  /**
   * @brief Append warnings/errors to the error message string.
   * @param errorMessage The error message to append.
   */
  void appendError(const std::string &errorMessage);

  class Destroyer;
  friend class Destroyer;
  static FileFormatManager* m_instance;
  static Destroyer m_destroyer;

  std::vector<FileFormat *> m_formats;
  std::map<std::string, size_t> m_identifiers;
  std::map<std::string, size_t> m_mimeTypes;
  std::multimap<std::string, size_t> m_fileExtensions;

  std::string m_error;
};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_FILEFORMATMANAGER_H
