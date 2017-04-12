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

#ifndef AVOGADRO_QTPLUGINS_FILEDIALOG_H
#define AVOGADRO_QTPLUGINS_FILEDIALOG_H

#include <QDialog>
#include <QStringList>

class QModelIndex;
class QPoint;
class QShowEvent;

namespace ProtoCall {
namespace Runtime {
class vtkCommunicatorChannel;
}
}

/**
 * @class FileDialog filedialog.h <avogadro/qtplugins/clientserver/filedialog.h>
 * @brief Remote file dialog
 */
class FileDialog : public QDialog
{
  Q_OBJECT
public:
  FileDialog(ProtoCall::Runtime::vtkCommunicatorChannel*, QWidget* Parent,
             const QString& Title = QString(),
             const QString& Directory = QString(),
             const QString& Filter = QString());
  ~FileDialog();

  /// set the most recently used file extension
  void setRecentlyUsedExtension(const QString& fileExtension);

  /// Returns all the file groups
  QString getSelectedFile();

  /// accept this dialog
  void accept();

  /// set a file current to support test playback
  bool selectFile(const QString&);

  /// set if we show hidden files and holders
  void setShowHidden(const bool& hidden);

  /// returns the state of the show hidden flag
  bool getShowHidden();

signals:
  /// Signal emitted when the user has chosen a file
  void fileSelected(const QString&);

  void fileAcceptedInternal(const QString&);

  friend class AcceptRequest;

protected:
  void acceptExistingFiles();
  void acceptDefault();

  QStringList buildFileGroup(const QString& filename);

  virtual void showEvent(QShowEvent* showEvent);

private slots:
  void onModelReset();
  void onNavigate(const QString&);
  void onNavigateUp();
  void onNavigateBack();
  void onNavigateForward();
  void onNavigateDown(const QModelIndex&);
  void onFilterChange(const QString&);

  void onDoubleClickFile(const QModelIndex&);

  void onTextEdited(const QString&);

  void onShowHiddenFiles(const bool& hide);

  // Called when the user changes the file selection.
  void fileSelectionChanged();

  // Called when the user right-clicks in the file qtreeview
  void onContextMenuRequested(const QPoint& pos);

  // Set the selected file
  void setSelectedFile(const QString&);

  // Emits the filesSelected() signal and closes the dialog,
  void emitFilesSelectionDone();

  void acceptRequestFinished(bool accept);

private:
  FileDialog(const FileDialog&);
  FileDialog& operator=(const FileDialog&);

  class Private;
  Private* const m_implementation;

  // returns if true if files are loaded
  void acceptInternal(const QStringList& selected_files,
                      const bool& doubleclicked);
  QString fixFileExtension(const QString& filename, const QString& filter);
};

#endif
