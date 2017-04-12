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

#include "filedialog.h"
#include "filedialogfilter.h"
#include "filedialogmodel.h"
#include <protocall/runtime/vtkcommunicatorchannel.h>

#include <QAbstractButton>
#include <QAbstractItemView>
#include <QAction>
#include <QComboBox>
#include <QCompleter>
#include <QDir>
#include <QKeyEvent>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMouseEvent>
#include <QPoint>
#include <QPointer>
#include <QShowEvent>
#include <QStringList>
#include <QtCore/QObject>
#include <QtDebug>

#include <string>
#include <vtksys/SystemTools.hxx>

using ProtoCall::Runtime::vtkCommunicatorChannel;

class FileComboBox : public QComboBox
{
public:
  FileComboBox(QWidget* p) : QComboBox(p) {}
  void showPopup()
  {
    QWidget* container = view()->parentWidget();
    container->setMaximumWidth(width());
    QComboBox::showPopup();
  }
};

#include "ui_filedialog.h"

namespace {

QStringList makeFilterList(const QString& filter)
{
  QString f(filter);

  if (f.isEmpty())
    return QStringList();

  QString sep(";;");
  int i = f.indexOf(sep, 0);
  if (i == -1) {
    if (f.indexOf("\n", 0) != -1) {
      sep = "\n";
      i = f.indexOf(sep, 0);
    }
  }
  return f.split(sep, QString::SkipEmptyParts);
}

QStringList getWildCardsFromFilter(const QString& filter)
{
  QString f = filter;
  int start, end;
  start = filter.indexOf('(');
  end = filter.lastIndexOf(')');
  if (start != -1 && end != -1) {
    f = f.mid(start + 1, end - start - 1);
  } else if (start != -1 || end != -1) {
    f = QString(); // hmm...  I'm confused
  }

  // separated by spaces or semi-colons
  QStringList fs = f.split(QRegExp("[\\s+;]"), QString::SkipEmptyParts);

  // add a *.ext.* for every *.ext we get to support file groups
  QStringList ret = fs;
  foreach (QString ext, fs) {
    ret.append(ext + ".*");
  }
  return ret;
}
}

class FileDialog::Private : public QObject
{
public:
  FileDialogModel* const m_model;
  FileDialogFilter m_fileFilter;
  QString m_fileName;
  QCompleter* m_completer;
  Ui::FileDialog m_ui;
  QString m_selectedFile;
  QStringList m_filters;

  // remember the last locations we browsed
  static QMap<vtkCommunicatorChannel*, QString> m_serverFilePaths;

  Private(FileDialog* p, vtkCommunicatorChannel* server)
    : QObject(p), m_model(new FileDialogModel(server, nullptr)),
      m_fileFilter(m_model), m_completer(new QCompleter(&m_fileFilter, nullptr))
  {
  }

  ~Private()
  {
    delete m_model;
    delete m_completer;
  }

  bool eventFilter(QObject* obj, QEvent* anEvent)
  {
    if (obj == m_ui.Files) {
      if (anEvent->type() == QEvent::KeyPress) {
        QKeyEvent* keyEvent = static_cast<QKeyEvent*>(anEvent);
        if (keyEvent->key() == Qt::Key_Backspace ||
            keyEvent->key() == Qt::Key_Delete) {
          m_ui.FileName->setFocus(Qt::OtherFocusReason);
          // send out a backspace event to the file name now
          QKeyEvent replicateDelete(keyEvent->type(), keyEvent->key(),
                                    keyEvent->modifiers());
          QApplication::sendEvent(m_ui.FileName, &replicateDelete);
          return true;
        }
      }
      return false;
    }
    return QObject::eventFilter(obj, anEvent);
  }

  QString getStartPath()
  {
    QMap<vtkCommunicatorChannel*, QString>::iterator iter;
    iter = m_serverFilePaths.find(m_model->server());
    if (iter != m_serverFilePaths.end()) {
      return *iter;
    }

    return m_model->getCurrentPath();
  }

  void setCurrentPath(const QString& p)
  {
    m_model->setCurrentPath(p);
    vtkCommunicatorChannel* s = m_model->server();
    m_serverFilePaths[s] = p;
    m_ui.Files->setFocus(Qt::OtherFocusReason);
  }

  void addHistory(const QString& p)
  {
    m_backHistory.append(p);
    m_forwardHistory.clear();

    if (m_backHistory.size() > 1)
      m_ui.NavigateBack->setEnabled(true);
    else
      m_ui.NavigateBack->setEnabled(false);

    m_ui.NavigateForward->setEnabled(false);
  }

  QString backHistory()
  {
    QString path = m_backHistory.takeLast();
    m_forwardHistory.append(m_model->getCurrentPath());
    m_ui.NavigateForward->setEnabled(true);
    if (m_backHistory.size() == 1)
      m_ui.NavigateBack->setEnabled(false);

    return path;
  }

  QString forwardHistory()
  {
    QString path = m_forwardHistory.takeLast();
    m_backHistory.append(m_model->getCurrentPath());
    m_ui.NavigateBack->setEnabled(true);
    if (m_forwardHistory.size() == 0) {
      m_ui.NavigateForward->setEnabled(false);
    }

    return path;
  }

protected:
  QStringList m_backHistory;
  QStringList m_forwardHistory;
};

QMap<vtkCommunicatorChannel*, QString> FileDialog::Private::m_serverFilePaths;

/////////////////////////////////////////////////////////////////////////////
// FileDialog

FileDialog::FileDialog(vtkCommunicatorChannel* server, QWidget* p,
                       const QString& title, const QString& startDirectory,
                       const QString& nameFilter)
  : QDialog(p), m_implementation(new Private(this, server))
{
  m_implementation->m_ui.setupUi(this);
  // ensures that the favorites and the browser component are sized
  // proportionately.
  m_implementation->m_ui.mainSplitter->setStretchFactor(0, 1);
  m_implementation->m_ui.mainSplitter->setStretchFactor(1, 4);
  setWindowTitle(title);

  m_implementation->m_ui.Files->setEditTriggers(
    QAbstractItemView::EditKeyPressed);

  // install the event filter
  m_implementation->m_ui.Files->installEventFilter(m_implementation);

  // install the autocompleter
  m_implementation->m_ui.FileName->setCompleter(m_implementation->m_completer);

  QPixmap back = style()->standardPixmap(QStyle::SP_FileDialogBack);
  m_implementation->m_ui.NavigateBack->setIcon(back);
  m_implementation->m_ui.NavigateBack->setEnabled(false);
  QObject::connect(m_implementation->m_ui.NavigateBack, SIGNAL(clicked(bool)),
                   this, SLOT(onNavigateBack()));
  // just flip the back image to make a forward image
  QPixmap forward = QPixmap::fromImage(back.toImage().mirrored(true, false));
  m_implementation->m_ui.NavigateForward->setIcon(forward);
  m_implementation->m_ui.NavigateForward->setDisabled(true);
  QObject::connect(m_implementation->m_ui.NavigateForward,
                   SIGNAL(clicked(bool)), this, SLOT(onNavigateForward()));
  m_implementation->m_ui.NavigateUp->setIcon(
    style()->standardPixmap(QStyle::SP_FileDialogToParent));

  m_implementation->m_ui.Files->setModel(&m_implementation->m_fileFilter);
  m_implementation->m_ui.Files->setSelectionBehavior(
    QAbstractItemView::SelectRows);

  m_implementation->m_ui.Files->setContextMenuPolicy(Qt::CustomContextMenu);
  QObject::connect(m_implementation->m_ui.Files,
                   SIGNAL(customContextMenuRequested(const QPoint&)), this,
                   SLOT(onContextMenuRequested(const QPoint&)));

  QObject::connect(m_implementation->m_model, SIGNAL(modelReset()), this,
                   SLOT(onModelReset()));

  QObject::connect(m_implementation->m_ui.NavigateUp, SIGNAL(clicked()), this,
                   SLOT(onNavigateUp()));

  QObject::connect(m_implementation->m_ui.Parents,
                   SIGNAL(activated(const QString&)), this,
                   SLOT(onNavigate(const QString&)));

  QObject::connect(m_implementation->m_ui.FileType,
                   SIGNAL(currentIndexChanged(const QString&)), this,
                   SLOT(onFilterChange(const QString&)));

  QObject::connect(
    m_implementation->m_ui.Files->selectionModel(),
    SIGNAL(selectionChanged(const QItemSelection&, const QItemSelection&)),
    this, SLOT(fileSelectionChanged()));

  QObject::connect(m_implementation->m_ui.Files,
                   SIGNAL(doubleClicked(const QModelIndex&)), this,
                   SLOT(onDoubleClickFile(const QModelIndex&)));

  QObject::connect(m_implementation->m_ui.FileName,
                   SIGNAL(textChanged(const QString&)), this,
                   SLOT(onTextEdited(const QString&)));

  QStringList filterList = makeFilterList(nameFilter);
  if (filterList.empty()) {
    m_implementation->m_ui.FileType->addItem("All Files (*)");
    m_implementation->m_filters << "All Files (*)";
  } else {
    m_implementation->m_ui.FileType->addItems(filterList);
    m_implementation->m_filters = filterList;
  }
  onFilterChange(m_implementation->m_ui.FileType->currentText());

  QString startPath = startDirectory;

  if (startPath.isEmpty()) {
    startPath = m_implementation->getStartPath();
  }
  m_implementation->addHistory(startPath);
  m_implementation->setCurrentPath(startPath);
}

//-----------------------------------------------------------------------------
FileDialog::~FileDialog()
{
}

//-----------------------------------------------------------------------------
void FileDialog::onContextMenuRequested(const QPoint& menuPos)
{
  QMenu menu;
  menu.setObjectName("FileDialogContextMenu");

  QAction* actionHiddenFiles = new QAction("Show Hidden Files", this);
  actionHiddenFiles->setCheckable(true);
  actionHiddenFiles->setChecked(m_implementation->m_fileFilter.getShowHidden());
  QObject::connect(actionHiddenFiles, SIGNAL(triggered(bool)), this,
                   SLOT(onShowHiddenFiles(bool)));
  menu.addAction(actionHiddenFiles);

  menu.exec(m_implementation->m_ui.Files->mapToGlobal(menuPos));
}

//-----------------------------------------------------------------------------
void FileDialog::setRecentlyUsedExtension(const QString& fileExtension)
{
  if (fileExtension.isEmpty()) {
    // upon the initial use of any kind (e.g., data or screenshot) of dialog
    // 'fileExtension' is equal /set to an empty string.
    // In this case, no any user preferences are considered
    m_implementation->m_ui.FileType->setCurrentIndex(0);
  } else {
    int index = m_implementation->m_ui.FileType->findText(fileExtension,
                                                          Qt::MatchContains);
    // just in case the provided extension is not in the combobox list
    index = (index == -1) ? 0 : index;
    m_implementation->m_ui.FileType->setCurrentIndex(index);
  }
}

//-----------------------------------------------------------------------------
void FileDialog::setSelectedFile(const QString& file)
{
  // Ensure that we are hidden before broadcasting the selection,
  // so we don't get caught by screen-captures
  setVisible(false);
  m_implementation->m_selectedFile = file;
}

//-----------------------------------------------------------------------------
void FileDialog::emitFilesSelectionDone()
{
  emit fileSelected(m_implementation->m_selectedFile);
  done(QDialog::Accepted);
}

//-----------------------------------------------------------------------------
QString FileDialog::getSelectedFile()
{
  return m_implementation->m_selectedFile;
}

//-----------------------------------------------------------------------------
void FileDialog::accept()
{
  acceptExistingFiles();
}

class AcceptRequest : public QObject
{
  Q_OBJECT
public:
  AcceptRequest(FileDialog* dialog, const QString& selectedFile,
                bool doubleClicked)
    : m_dialog(dialog), m_selectedFile(selectedFile),
      m_doubleClicked(doubleClicked)
  {
  }

public slots:
  void accept()
  {
    if (m_selectedFile.isEmpty()) {
      emit finished(false);
      return;
    }

    accept(m_selectedFile);
  }

  void accept(const QString& file)
  {
    // Connect up cleanup slot
    connect(this, SIGNAL(finished(bool)), this, SLOT(cleanup()));

    if (file.isEmpty()) {
      emit finished(false);
      return;
    }
    // User chose an existing directory
    m_dialog->m_implementation->m_model->dirExists(
      file, this, SLOT(onDirExists(const QString, bool)));
  }

  void onDirExists(const QString& path, bool exists)
  {

    if (exists) {
      acceptExistingDirectory(path);
    } else {
      acceptFile(path);
    }
  }

  void acceptExistingDirectory(const QString& file)
  {
    m_dialog->onNavigate(file);
    emit finished(false);
  }

  void acceptFile(const QString& file)
  {
    m_dialog->m_implementation->m_model->fileExists(
      file, this, SLOT(onFileExistsComplete(const QString, bool)));
  }

  void acceptOnDirExists(const QString& dir, bool exists)
  {
    if (exists) {
      m_dialog->onNavigate(dir);
      m_dialog->m_implementation->m_ui.FileName->clear();
      emit finished(false);
    } else {
      m_dialog->m_implementation->m_model->fileExists(
        m_selectedFile, this, SLOT(onFileExistsComplete));
    }
  }

  void onFileExistsComplete(const QString& file, bool exists)
  {
    if (exists) {
      m_dialog->setSelectedFile(file);
      emit finished(true);
      return;
    } else {
      m_dialog->m_implementation->m_ui.FileName->selectAll();
      emit finished(false);
      return;
    }

    emit finished(false);
  }

  void cleanup()
  {
    AcceptRequest* request = qobject_cast<AcceptRequest*>(sender());

    if (request)
      delete request;
  }

signals:
  void finished(bool accept);

private:
  FileDialog* m_dialog;
  QString m_selectedFile;
  bool m_doubleClicked;
};

//-----------------------------------------------------------------------------
void FileDialog::acceptExistingFiles()
{
  QString filename;
  if (m_implementation->m_fileName.isEmpty()) {
    // when we have nothing selected in the current selection model, we will
    // attempt to use the default way
    acceptDefault();
  }

  AcceptRequest* request =
    new AcceptRequest(this, m_implementation->m_fileName, false);

  connect(request, SIGNAL(finished(bool)), this,
          SLOT(acceptRequestFinished(bool)));

  m_implementation->m_model->absoluteFilePath(
    m_implementation->m_fileName, request, SLOT(accept(const QString&)));
}

void FileDialog::acceptRequestFinished(bool accept)
{
  if (accept)
    emit emitFilesSelectionDone();
}

//-----------------------------------------------------------------------------
void FileDialog::acceptDefault()
{
  QString filename = m_implementation->m_ui.FileName->text();
  filename = filename.trimmed();

  m_implementation->m_model->absoluteFilePath(
    filename, this, SLOT(acceptDefaultContinued(const QString&)));
}

//-----------------------------------------------------------------------------
void FileDialog::onModelReset()
{
  m_implementation->m_ui.Parents->clear();

  QString currentPath = m_implementation->m_model->getCurrentPath();
  // clean the path to always look like a unix path
  currentPath = QDir::cleanPath(currentPath);

  // the separator is always the unix separator
  QChar separator = '/';

  QStringList parents = currentPath.split(separator, QString::SkipEmptyParts);

  // put our root back in
  if (parents.count()) {
    int idx = currentPath.indexOf(parents[0]);
    if (idx != 0 && idx != -1)
      parents.prepend(currentPath.left(idx));

  } else {
    parents.prepend(separator);
  }

  for (int i = 0; i != parents.size(); ++i) {
    QString str;
    for (int j = 0; j <= i; j++) {
      str += parents[j];
      if (!str.endsWith(separator)) {
        str += separator;
      }
    }
    m_implementation->m_ui.Parents->addItem(str);
  }
  m_implementation->m_ui.Parents->setCurrentIndex(parents.size() - 1);
}

//-----------------------------------------------------------------------------
void FileDialog::onNavigate(const QString& Path)
{
  m_implementation->addHistory(m_implementation->m_model->getCurrentPath());
  m_implementation->setCurrentPath(Path);
}

//-----------------------------------------------------------------------------
void FileDialog::onNavigateUp()
{
  m_implementation->addHistory(m_implementation->m_model->getCurrentPath());
  QFileInfo info(m_implementation->m_model->getCurrentPath());
  m_implementation->setCurrentPath(info.path());
}

//-----------------------------------------------------------------------------
void FileDialog::onNavigateDown(const QModelIndex& idx)
{
  if (!m_implementation->m_model->isDir(idx))
    return;

  const QStringList paths = m_implementation->m_model->getFilePaths(idx);

  if (1 != paths.size())
    return;

  m_implementation->addHistory(m_implementation->m_model->getCurrentPath());
  m_implementation->setCurrentPath(paths[0]);
}

//-----------------------------------------------------------------------------
void FileDialog::onNavigateBack()
{
  QString path = m_implementation->backHistory();
  m_implementation->setCurrentPath(path);
}

//-----------------------------------------------------------------------------
void FileDialog::onNavigateForward()
{
  QString path = m_implementation->forwardHistory();
  m_implementation->setCurrentPath(path);
}

//-----------------------------------------------------------------------------
void FileDialog::onFilterChange(const QString& filter)
{
  // set filter on proxy
  m_implementation->m_fileFilter.setFilter(filter);

  // update view
  m_implementation->m_fileFilter.clear();
}

//-----------------------------------------------------------------------------
void FileDialog::onDoubleClickFile(const QModelIndex& index)
{
  accept();
}

//-----------------------------------------------------------------------------
void FileDialog::onShowHiddenFiles(const bool& hidden)
{
  m_implementation->m_fileFilter.setShowHidden(hidden);
}

//-----------------------------------------------------------------------------
void FileDialog::setShowHidden(const bool& hidden)
{
  onShowHiddenFiles(hidden);
}

//-----------------------------------------------------------------------------
bool FileDialog::getShowHidden()
{
  return m_implementation->m_fileFilter.getShowHidden();
}

//-----------------------------------------------------------------------------
void FileDialog::onTextEdited(const QString& str)
{
  // really important to block signals so that the clearSelection
  // doesn't cause a signal to be fired that calls fileSelectionChanged
  m_implementation->m_ui.Files->blockSignals(true);
  m_implementation->m_ui.Files->clearSelection();
  if (str.size() > 0)
    m_implementation->m_fileName = str;
  else
    m_implementation->m_fileName.clear();

  m_implementation->m_ui.Files->blockSignals(false);
}

//-----------------------------------------------------------------------------
QString FileDialog::fixFileExtension(const QString& filename,
                                     const QString& filter)
{
  // Add missing extension if necessary
  QFileInfo fileInfo(filename);
  QString ext = fileInfo.completeSuffix();
  QString extensionWildcard = getWildCardsFromFilter(filter).first();
  QString wantedExtension =
    extensionWildcard.mid(extensionWildcard.indexOf('.') + 1);

  if (!ext.isEmpty()) {
    // Ensure that the extension the user added is indeed of one the supported
    // types. (BUG #7634).
    QStringList wildCards;
    foreach (QString curfilter, m_implementation->m_filters) {
      wildCards += ::getWildCardsFromFilter(curfilter);
    }
    bool pass = false;
    foreach (QString wildcard, wildCards) {
      if (wildcard.indexOf('.') != -1) {
        // we only need to validate the extension, not the filename.
        wildcard = QString("*.%1").arg(wildcard.mid(wildcard.indexOf('.') + 1));
        QRegExp regEx =
          QRegExp(wildcard, Qt::CaseInsensitive, QRegExp::Wildcard);
        if (regEx.exactMatch(fileInfo.fileName())) {
          pass = true;
          break;
        }
      } else {
        // we have a filter which does not specify any rule for the extension.
        // In that case, just assume the extension matched.
        pass = true;
        break;
      }
    }
    if (!pass) {
      // force adding of the wantedExtension.
      ext = QString();
    }
  }

  QString fixedFilename = filename;
  if (ext.isEmpty() && !wantedExtension.isEmpty() && wantedExtension != "*") {
    if (fixedFilename.at(fixedFilename.size() - 1) != '.')
      fixedFilename += ".";

    fixedFilename += wantedExtension;
  }
  return fixedFilename;
}

//-----------------------------------------------------------------------------
void FileDialog::fileSelectionChanged()
{
  // Selection changed, update the FileName entry box
  // to reflect the current selection.
  QString fileString;
  const QModelIndexList indices =
    m_implementation->m_ui.Files->selectionModel()->selectedIndexes();
  if (indices.isEmpty()) {
    // do not change the FileName text if no selections
    return;
  }
  QString fileName;

  QModelIndex index = indices[0];
  if (index.column() != 0)
    return;

  if (index.model() == &m_implementation->m_fileFilter)
    fileName = m_implementation->m_fileFilter.data(index).toString();

  // user is currently editing a name, don't change the text
  m_implementation->m_ui.FileName->blockSignals(true);
  m_implementation->m_ui.FileName->setText(fileString);
  m_implementation->m_ui.FileName->blockSignals(false);
  m_implementation->m_fileName = fileName;
}

//-----------------------------------------------------------------------------
bool FileDialog::selectFile(const QString& f)
{
  // We don't use QFileInfo here since it messes the paths up if the client and
  // the server are heterogeneous systems.
  std::string unix_path = f.toAscii().data();
  vtksys::SystemTools::ConvertToUnixSlashes(unix_path);

  std::string filename, dirname;
  std::string::size_type slashPos = unix_path.rfind("/");
  if (slashPos != std::string::npos) {
    filename = unix_path.substr(slashPos + 1);
    dirname = unix_path.substr(0, slashPos);
  } else {
    filename = unix_path;
    dirname = "";
  }

  QPointer<QDialog> diag = this;
  m_implementation->m_model->setCurrentPath(dirname.c_str());
  m_implementation->m_ui.FileName->setText(filename.c_str());
  accept();
  if (diag && diag->result() != QDialog::Accepted)
    return false;

  return true;
}

//-----------------------------------------------------------------------------
void FileDialog::showEvent(QShowEvent* _showEvent)
{
  QDialog::showEvent(_showEvent);
  // Qt sets the default keyboard focus to the last item in the tab order
  // which is determined by the creation order. This means that we have
  // to explicitly state that the line edit has the focus on showing no
  // matter the tab order
  m_implementation->m_ui.FileName->setFocus(Qt::OtherFocusReason);
}

#include "filedialog.moc"
