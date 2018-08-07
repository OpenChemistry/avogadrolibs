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

#ifndef AVOGADRO_QTGUI_FILEFORMATDIALOG_H
#define AVOGADRO_QTGUI_FILEFORMATDIALOG_H

#include "avogadroqtguiexport.h"
#include <QtWidgets/QFileDialog>

#include <avogadro/io/fileformat.h>

#include <vector>

namespace Avogadro {
namespace Core {
class Molecule;
}

namespace QtGui {
/**
 * @class FileFormatDialog fileformatdialog.h
 * <avogadro/qtgui/fileformatdialog.h>
 *
 * Allow users to select save/open filenames that can be handled by registered
 * FileFormats.
 */
class AVOGADROQTGUI_EXPORT FileFormatDialog : private QFileDialog
{
  Q_OBJECT
public:
  /**
   * Container for a filename and a compatible file format, used as return
   * values in static functions.
   * @note The FileFormat will be set to nullptr to indicate an error.
   * @note The FileFormat points to the reference instance held by the
   * FileFormatManager. Use FileFormat::newInstance() to create a usable copy.
   */
  typedef QPair<const Io::FileFormat*, QString> FormatFilePair;

  /**
   * @brief Show a QFileDialog to prompt the user for a file to open and resolve
   * any file format conflicts. This method returns the selected file and
   * FileFormat reader.
   * @param parent The parent of the dialog windows.
   * @param caption The dialog window titles.
   * @param dir The initial directory shown to the user.
   * @param filter A list of filters for limiting the files shown to the user.
   * See the QFileDialog documentation for format. If the string is empty, a
   * default list of all suitable registered formats will be used.
   * @return A FormatFilePair object containing the absolute file path and a
   * compatible file reader. If an error occurs, the format pointer will be
   * nullptr.
   */
  static FormatFilePair fileToRead(QWidget* parent,
                                   const QString& caption = QString(),
                                   const QString& dir = QString(),
                                   const QString& filter = QString());

  /**
   * @brief Show a QFileDialog to prompt the user for a file to save and resolve
   * any file format conflicts. This method returns the selected file and
   * FileFormat writer.
   * @param parent The parent of the dialog windows.
   * @param caption The dialog window titles.
   * @param dir The initial directory shown to the user.
   * @param filter A list of filters for limiting the files shown to the user.
   * See the QFileDialog documentation for format. If the string is empty, a
   * default list of all suitable registered formats will be used.
   * @return A FormatFilePair object containing the absolute file path and a
   * compatible file writer. If an error occurs, the format pointer will be
   * nullptr.
   */
  static FormatFilePair fileToWrite(QWidget* parent,
                                    const QString& caption = QString(),
                                    const QString& dir = QString(),
                                    const QString& filter = QString());

  /**
   * Given a filename and a set of Io::FileFormat::Operation flags, find a
   * suitable file format from the FileFormatManager. If multiple readers are
   * found, ask the user to select one. If no suitable format is found, return
   * nullptr.
   * @param parentWidget Parent for any dialog windows that will appear.
   * @param caption Window title for any dialog windows.
   * @param fileName Filename to use when searching for a format. Formats are
   * chosen based on the file extension.
   * @param formatFlags Operations that the format must support. Most likely
   * (Io::FileFormat::)Read | File or Write | File.
   * @param formatPrefix Filter on the supplied prefix (default to none).
   * @return The selected matching reader, or nullptr if no reader is found.
   */
  static const Io::FileFormat* findFileFormat(
    QWidget* parentWidget, const QString& caption, const QString& fileName,
    const Io::FileFormat::Operations formatFlags,
    const QString& formatPrefix = QString());

private:
  /**
   * Constructor is private for now to force use of static methods. This
   * may be made public at some point if additional API is needed or more
   * complex use cases arise.
   */
  explicit FileFormatDialog(QWidget* parent = nullptr);
  ~FileFormatDialog() override;

  /**
   * @return A filter string for use with a QFileDialog, containing entries
   * for all file extensions registered with FileFormatManager, as well as a
   * "catch-all" entry with all known formats, and an "All files (*)" entry.
   * Only formats registered with (Read | File) will be used.
   */
  static const QString readFileFilter();

  /**
   * @return A filter string for use with a QFileDialog, containing entries
   * for all file extensions registered with FileFormatManager. An
   * "All files (*)" entry is added as well.
   * Only formats registered with (Write | File) will be used.
   */
  static const QString writeFileFilter();

  /**
   * Used internally by readFileFilter() and writeFileFilter().
   * @{
   */
public: // Must be public for operator declarations
  enum FilterStringOption
  {
    NoFilterStringOption = 0x0,
    AllFormats = 0x1,
    AllFiles = 0x2
  };
  Q_DECLARE_FLAGS(FilterStringOptions, FilterStringOption)

private:
  static QString generateFilterString(
    const std::vector<const Io::FileFormat*>& ffs, FilterStringOptions options);
  /** @} */

  /**
   * Show a dialog to resolve file format conflicts. This allows the user to
   * select between multiple instances of FileFormat that can handle their
   * chosen file extension.
   * @param parentWidget Widget to use as dialog parent.
   * @param ffs Conflicting FileFormats that the user should choose from.
   * @param caption The title of the dialog window.
   * @param prompt The text in the dialog window.
   * @param settingsKey An optional QSettings key that will be used to
   * store the user's choice for initializing the dialog next time.
   * @return The selected FileFormat instance.
   */
  static const Io::FileFormat* selectFileFormat(
    QWidget* parentWidget, const std::vector<const Io::FileFormat*>& ffs,
    const QString& caption, const QString& prompt,
    const QString& settingsKey = QString(),
    const QString& formatPrefix = QString());
};

} // namespace QtGui
} // namespace Avogadro

Q_DECLARE_OPERATORS_FOR_FLAGS(
  Avogadro::QtGui::FileFormatDialog::FilterStringOptions)

#endif // AVOGADRO_QTGUI_FILEFORMATDIALOG_H
