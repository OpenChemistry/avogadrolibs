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

#include "fileformatdialog.h"

#include <avogadro/core/molecule.h>
#include <avogadro/io/fileformatmanager.h>

#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>

#include <QtCore/QSettings>

#include <vector>

using Avogadro::Io::FileFormat;
using Avogadro::Io::FileFormatManager;
using std::vector;

namespace Avogadro {
namespace QtGui {

FileFormatDialog::FileFormatDialog(QWidget* parentW)
  : QFileDialog(parentW)
{}

FileFormatDialog::~FileFormatDialog() {}

FileFormatDialog::FormatFilePair FileFormatDialog::fileToRead(
  QWidget* parent, const QString& caption, const QString& dir,
  const QString& filter)
{
  FormatFilePair result(nullptr, QString());
  // Use the default read filter if none specified:
  const QString realFilter = filter.isEmpty() ? readFileFilter() : filter;

  bool done = false;
  do { // jump point for continue statements on retry
    QString fileName =
      QFileDialog::getOpenFileName(parent, caption, dir, realFilter);

    if (fileName.isEmpty()) // user cancel
      return result;

    const Io::FileFormat* format = findFileFormat(
      parent, caption, fileName, FileFormat::File | FileFormat::Read);

    // If none found, give user the option to retry.
    if (!format) {
      QMessageBox::StandardButton reply = QMessageBox::question(
        parent, caption,
        tr("Unable to find a suitable file reader for "
           "the selected file."),
        QMessageBox::Abort | QMessageBox::Retry, QMessageBox::Retry);
      switch (reply) {
        default:
        case QMessageBox::Retry:
          continue;
        case QMessageBox::Abort:
          return result;
      }
    }

    result.first = format;
    result.second = fileName;
    done = true;

  } while (!done);

  return result;
}

FileFormatDialog::FormatFilePair FileFormatDialog::fileToWrite(
  QWidget* parentWidget, const QString& caption, const QString& dir,
  const QString& filter)
{
  FormatFilePair result(nullptr, QString());
  // Use the default read filter if none specified:
  const QString realFilter = filter.isEmpty() ? writeFileFilter() : filter;
  
QString fileName;
  do { // jump point for continue statements on retry
    fileName =
      QFileDialog::getSaveFileName(parentWidget, caption, dir, realFilter);

    if (fileName.isEmpty()) // user cancel
      return result;

    const Io::FileFormat* format = findFileFormat(
      parentWidget, caption, fileName, FileFormat::File | FileFormat::Write);

    // If none found, give user the option to retry.
    if (!format) {
      QMessageBox::StandardButton reply = QMessageBox::question(
        parentWidget, caption,
        tr("Unable to find a suitable file writer for "
           "the selected format."),
        QMessageBox::Abort | QMessageBox::Retry, QMessageBox::Retry);
      switch (reply) {
        default:
        case QMessageBox::Retry:
          continue;
        case QMessageBox::Abort:
          return result;
      }
    }

    result.first = format;
    result.second = fileName;

  } while (fileName.isEmpty());

  return result;
}

const Io::FileFormat* FileFormatDialog::findFileFormat(
  QWidget* parentWidget, const QString& caption, const QString& fileName,
  const FileFormat::Operations formatFlags, const QString& formatPrefix)
{
  if (fileName.isEmpty())
    return nullptr;

  // Extract extension from filename.
  QFileInfo fileInfo(fileName);
  QString extension = fileInfo.suffix();
  if (extension.isEmpty())
    extension = fileInfo.fileName();

  // Lookup matching file formats.
  vector<const FileFormat*> matches(
    FileFormatManager::instance().fileFormatsFromFileExtension(
      extension.toStdString(), formatFlags));

  // Prepare the strings for selectFileFormat:
  QString noun;
  QString verb;
  QString key;

  if ((formatFlags & FileFormat::Read && formatFlags & FileFormat::Write) ||
      ((formatFlags & FileFormat::Read) == 0 &&
       (formatFlags & FileFormat::Write) == 0)) {
    // Both or neither read/write
    noun = tr("handlers", "File handlers");
    verb = tr("handle", "e.g. file handlers that can 'handle' this file.");
    key = QLatin1String("fileToWrite"); // Just use the write settings
  } else if (formatFlags & FileFormat::Read) {
    // Read
    noun = tr("readers", "File readers");
    verb = tr("read", "e.g. file readers that can 'read' this file.");
    key = QLatin1String("fileToRead");
  } else if (formatFlags & FileFormat::Write) {
    // Write
    noun = tr("writers", "File writers");
    verb = tr("write", "e.g. file writers that can 'write' this file.");
    key = QLatin1String("fileToWrite");
  }

  return selectFileFormat(parentWidget, matches, caption,
                          tr("Multiple %1 found that can %2 this format. "
                             "Which should be used?")
                            .arg(noun, verb),
                          QString("FileFormatDialog/%1/%2"
                                  "/lastUsed")
                            .arg(key, extension),
                          formatPrefix);
}

const QString FileFormatDialog::readFileFilter()
{
  static QString readFilter;
  if (readFilter.isEmpty()) {
    vector<const FileFormat*> formats =
      FileFormatManager::instance().fileFormats(FileFormat::Read |
                                                FileFormat::File);

    readFilter = generateFilterString(formats, AllFiles | AllFormats);
  }

  return readFilter;
}

const QString FileFormatDialog::writeFileFilter()
{
  static QString writeFilter;
  if (writeFilter.isEmpty()) {
    vector<const FileFormat*> formats =
      FileFormatManager::instance().fileFormats(FileFormat::Write |
                                                FileFormat::File);

    writeFilter = generateFilterString(formats, AllFiles);
  }

  return writeFilter;
}

QString FileFormatDialog::generateFilterString(
  const std::vector<const Io::FileFormat*>& ffs,
  FileFormatDialog::FilterStringOptions options)
{
  QString filterString;
  // Create a map that groups the file extensions by name:
  QMap<QString, QString> formatMap;
  for (std::vector<const Io::FileFormat*>::const_iterator it = ffs.begin(),
                                                          itEnd = ffs.end();
       it != itEnd; ++it) {
    QString name(QString::fromStdString((*it)->name()));
    std::vector<std::string> exts = (*it)->fileExtensions();
    for (std::vector<std::string>::const_iterator eit = exts.begin(),
                                                  eitEnd = exts.end();
         eit != eitEnd; ++eit) {
      QString ext(QString::fromStdString(*eit));
      if (!formatMap.values(name).contains(ext)) {
        formatMap.insertMulti(name, ext);
      }
    }
  }

  // This is a list of "extensions" returned by OB that are not actually
  // file extensions, but rather the full filename of the file. These
  // will be used as-is in the filter string, while others will be prepended
  // with "*.".
  QStringList nonExtensions;
  nonExtensions << QStringLiteral("POSCAR")  // VASP input geometry
                << QStringLiteral("CONTCAR") // VASP output geometry
                << QStringLiteral("HISTORY") // DL-POLY history file
                << QStringLiteral("CONFIG")  // DL-POLY config file
    ;

  // This holds all known extensions:
  QStringList allExtensions;

  foreach (const QString& desc, formatMap.uniqueKeys()) {
    QStringList extensions;
    foreach (QString extension, formatMap.values(desc)) {
      if (!nonExtensions.contains(extension))
        extension.prepend("*.");
      extensions << extension;
    }
    if (options & AllFormats)
      allExtensions << extensions;
    filterString += QStringLiteral("%1 (%2);;")
                      .arg(desc, extensions.join(QStringLiteral(" ")));
  }

  if (options & AllFiles)
    filterString.prepend(tr("All files (*);;"));

  if (options & AllFormats) {
    filterString.prepend(tr("All supported formats (%1);;")
                           .arg(allExtensions.join(QStringLiteral(" "))));
  }

  return filterString;
}

const Io::FileFormat* FileFormatDialog::selectFileFormat(
  QWidget* parentWidget, const std::vector<const Io::FileFormat*>& ffs,
  const QString& caption, const QString& prompt, const QString& settingsKey,
  const QString& formatPrefix)
{
  if (ffs.empty())
    return nullptr;
  else if (ffs.size() == 1)
    return ffs[0];

  // If more than one format found, prompt user to select one.
  QStringList idents;
  for (std::vector<const Io::FileFormat*>::const_iterator it = ffs.begin(),
                                                          itEnd = ffs.end();
       it != itEnd; ++it) {
    idents << QString::fromStdString((*it)->identifier());
  }

  // If there is a format prefix, see if that can reduce the results down.
  QStringList preferred;
  foreach (const QString& id, idents)
    if (id.startsWith(formatPrefix))
      preferred << id;
  if (preferred.size() == 1)
    return ffs[idents.indexOf(preferred.first())];

  // See if they used one before:
  QString lastIdent = settingsKey.isNull()
                        ? QString()
                        : QSettings().value(settingsKey).toString();

  int lastIdentIndex = idents.indexOf(lastIdent);
  if (lastIdentIndex < 0)
    lastIdentIndex = 0;

  bool ok;
  QString item = QInputDialog::getItem(parentWidget, caption, prompt, idents,
                                       lastIdentIndex, false, &ok);
  int index = idents.indexOf(item);

  // user cancel
  if (!ok || index < 0 || index + 1 > static_cast<int>(ffs.size()))
    return nullptr;

  // Store chosen reader for next time
  if (!settingsKey.isNull())
    QSettings().setValue(settingsKey, item);

  return ffs[index];
}

} // namespace QtGui
} // namespace Avogadro
