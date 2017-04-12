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

#include "filedialogmodel.h"

#include <QApplication>
#include <QDebug>
#include <QDir>
#include <QMessageBox>
#include <QStyle>
#include <QtCore/QObject>

#include <vtkDirectory.h>
#include <vtkSmartPointer.h>

#include "RemoteFileSystemService.pb.h"
#include <google/protobuf/stubs/common.h>
#include <protocall/runtime/vtkcommunicatorchannel.h>

using namespace ProtoCall::Runtime;
using namespace google::protobuf;

// FileDialogModelFileInfo

class FileDialogModelFileInfo
{
public:
  FileDialogModelFileInfo() : m_type(FileDialogModel::INVALID), m_hidden(false)
  {
  }

  FileDialogModelFileInfo(
    const QString& l, const QString& filepath, FileDialogModel::FileType t,
    const bool& h,
    const QList<FileDialogModelFileInfo>& g = QList<FileDialogModelFileInfo>())
    : m_label(l), m_filePath(filepath), m_type(t), m_hidden(h), m_group(g)
  {
  }

  const QString& label() const { return m_label; }

  const QString& filePath() const { return m_filePath; }

  FileDialogModel::FileType type() const { return m_type; }

  bool isGroup() const { return !m_group.empty(); }

  bool isHidden() const { return m_hidden; }

  const QList<FileDialogModelFileInfo>& group() const { return m_group; }

private:
  QString m_label;
  QString m_filePath;
  FileDialogModel::FileType m_type;
  bool m_hidden;
  QList<FileDialogModelFileInfo> m_group;
};

/////////////////////////////////////////////////////////////////////
// Icons

FileDialogModelIconProvider::FileDialogModelIconProvider()
{
  QStyle* style = QApplication::style();
  m_folderLinkIcon = style->standardIcon(QStyle::SP_DirLinkIcon);
  m_fileLinkIcon = style->standardIcon(QStyle::SP_FileLinkIcon);
}

QIcon FileDialogModelIconProvider::icon(IconType t) const
{
  switch (t) {
    case Computer:
      return QFileIconProvider::icon(QFileIconProvider::Computer);
    case Drive:
      return QFileIconProvider::icon(QFileIconProvider::Drive);
    case Folder:
      return QFileIconProvider::icon(QFileIconProvider::Folder);
    case File:
      return QFileIconProvider::icon(QFileIconProvider::File);
    case FolderLink:
      return m_folderLinkIcon;
    case FileLink:
      return m_fileLinkIcon;
    case NetworkFolder:
      return QFileIconProvider::icon(QFileIconProvider::Network);
  }
  return QIcon();
}

QIcon FileDialogModelIconProvider::icon(FileDialogModel::FileType f) const
{
  if (f == FileDialogModel::DIRECTORY_LINK) {
    return icon(FileDialogModelIconProvider::FolderLink);
  } else if (f == FileDialogModel::SINGLE_FILE_LINK) {
    return icon(FileDialogModelIconProvider::FileLink);
  } else if (f == FileDialogModel::NETWORK_SHARE) {
    return icon(FileDialogModelIconProvider::NetworkFolder);
  } else if (f == FileDialogModel::NETWORK_SERVER) {
    return icon(FileDialogModelIconProvider::Computer);
  } else if (f == FileDialogModel::DIRECTORY) {
    return icon(FileDialogModelIconProvider::Folder);
  }

  return icon(FileDialogModelIconProvider::File);
}
QIcon FileDialogModelIconProvider::icon(const QFileInfo& info) const
{
  return QFileIconProvider::icon(info);
}
QIcon FileDialogModelIconProvider::icon(QFileIconProvider::IconType ico) const
{
  return QFileIconProvider::icon(ico);
}

Q_GLOBAL_STATIC(FileDialogModelIconProvider, Icons)

namespace {

///////////////////////////////////////////////////////////////////////
// caseInsensitiveSort

bool caseInsensitiveSort(const FileDialogModelFileInfo& A,
                         const FileDialogModelFileInfo& B)
{
  // Sort alphabetically (but case-insensitively)
  return A.label().toLower() < B.label().toLower();
}

} // namespace

class FileDialogModel::Private
{
public:
  Private(FileDialogModel* model,
          ProtoCall::Runtime::vtkCommunicatorChannel* server)
    : m_separator(0), m_server(server), m_model(model)
  {
    RemoteFileSystemService::Proxy proxy(m_server);

    // Get the separator
    Separator* separator = new Separator();
    Closure* callback = NewCallback(
      this, &FileDialogModel::Private::handleSeparatorResponse, separator);

    proxy.separator(separator, callback);
  }

  ~Private() {}

  void listCurrentWorkingDir()
  {
    Path dir;
    listDirectory(dir);
  }

  void listDirectory(const QString& path)
  {
    // Get the listing of the current working directory
    Path dir;
    dir.set_path(path.toStdString());

    listDirectory(dir);
  }

  void listDirectory(Path& dir)
  {

    RemoteFileSystemService::Proxy proxy(m_server);

    // Get the listing of the current working directory
    Listing* listing = new Listing();

    Closure* callback = NewCallback(
      this, &FileDialogModel::Private::handleListingResponse, listing);

    proxy.ls(&dir, listing, callback);
  }

  void handleSeparatorResponse(Separator* response)
  {
    m_separator = response->separator()[0];
    delete response;
  }

  void handleListingResponse(Listing* response)
  {
    m_currentPath = response->path().path().c_str();
    m_fileList.clear();

    QList<FileDialogModelFileInfo> dirs;
    QList<FileDialogModelFileInfo> files;

    for (int i = 0; i < response->paths_size(); i++) {
      const Path& path = response->paths(i);

      const QString label = QString::fromStdString(path.name());

      FileDialogModelFileInfo info(
        label, label, static_cast<FileDialogModel::FileType>(path.type()),
        false);

      if (path.type() == FileDialogModel::DIRECTORY) {
        dirs.push_back(info);
      } else {
        files.push_back(info);
      }
    }

    qSort(dirs.begin(), dirs.end(), caseInsensitiveSort);
    qSort(files.begin(), files.end(), caseInsensitiveSort);

    for (int i = 0; i != dirs.size(); ++i) {
      m_fileList.push_back(dirs[i]);
    }
    for (int i = 0; i != files.size(); ++i) {
      m_fileList.push_back(files[i]);
    }

    m_model->reset();

    delete response;
  }

  /// Removes multiple-slashes, ".", and ".." from the given path string,
  /// and points slashes in the correct direction for the server
  const QString cleanPath(const QString& Path)
  {
    QString result = QDir::cleanPath(QDir::fromNativeSeparators(Path));
    return result.trimmed();
  }

  QStringList getFilePaths(const QModelIndex& Index)
  {
    QStringList results;

    QModelIndex p = Index.parent();
    if (p.isValid()) {
      if (p.row() < m_fileList.size()) {
        FileDialogModelFileInfo& file = m_fileList[p.row()];
        const QList<FileDialogModelFileInfo>& grp = file.group();
        if (Index.row() < grp.size())
          results.push_back(grp[Index.row()].filePath());
      }
    } else if (Index.row() < m_fileList.size()) {
      FileDialogModelFileInfo& file = m_fileList[Index.row()];
      if (file.isGroup() && file.group().count() > 0) {
        for (int i = 0; i < file.group().count(); i++)
          results.push_back(file.group().at(i).filePath());

      } else
        results.push_back(file.filePath());
    }

    return results;
  }

  bool isHidden(const QModelIndex& idx)
  {
    const FileDialogModelFileInfo* info = infoForIndex(idx);
    return info ? info->isHidden() : false;
  }

  bool isDir(const QModelIndex& idx)
  {
    const FileDialogModelFileInfo* info = infoForIndex(idx);
    return info ? isDirectory(info->type()) : false;
  }

  bool isRemote() { return m_server; }

  ProtoCall::Runtime::vtkCommunicatorChannel* getServer() { return m_server; }

  /// Path separator for the connected server's filesystem.
  char m_separator;

  /// Current path being displayed (server's filesystem).
  QString m_currentPath;
  /// Caches information about the set of files within the current path.
  QVector<FileDialogModelFileInfo> m_fileList;

  const FileDialogModelFileInfo* infoForIndex(const QModelIndex& idx) const
  {
    if (idx.isValid() && nullptr == idx.internalPointer() && idx.row() >= 0 &&
        idx.row() < m_fileList.size()) {
      return &m_fileList[idx.row()];
    } else if (idx.isValid() && idx.internalPointer()) {
      FileDialogModelFileInfo* ptr =
        reinterpret_cast<FileDialogModelFileInfo*>(idx.internalPointer());
      const QList<FileDialogModelFileInfo>& grp = ptr->group();
      if (idx.row() >= 0 && idx.row() < grp.size()) {
        return &grp[idx.row()];
        ;
      }
    }

    return nullptr;
  }

private:
  ProtoCall::Runtime::vtkCommunicatorChannel* m_server;
  FileDialogModel* m_model;
};

//////////////////////////////////////////////////////////////////////////
// FileDialogModel
FileDialogModel::FileDialogModel(
  ProtoCall::Runtime::vtkCommunicatorChannel* _server, QObject* Parent)
  : base(Parent), m_implementation(new Private(this, _server))
{
}

FileDialogModel::~FileDialogModel()
{
  delete m_implementation;
}

ProtoCall::Runtime::vtkCommunicatorChannel* FileDialogModel::server() const
{
  return m_implementation->getServer();
}

void FileDialogModel::setCurrentPath(const QString& path)
{
  if (path.isEmpty())
    m_implementation->listCurrentWorkingDir();
  else
    m_implementation->listDirectory(path);
}

QString FileDialogModel::getCurrentPath()
{
  return m_implementation->m_currentPath;
}

class AbsoluteFilePathRequest : public QObject
{
  Q_OBJECT
public:
  AbsoluteFilePathRequest(vtkCommunicatorChannel* server,
                          const QString& currentDir, const QString& path)
    : m_currentDir(currentDir), m_path(path), m_server(server)
  {
  }

  void handleAbsolutePathResponse(Path* response)
  {
    emit complete(QString::fromStdString(response->path()));
    delete response;
  }

  void execute()
  {

    if (m_path.isEmpty()) {
      emit complete(QString());
    }

    RemoteFileSystemService::Proxy proxy(m_server);
    Path absolutePathRequest;
    absolutePathRequest.set_name(m_path.toStdString());
    absolutePathRequest.set_path(m_currentDir.toStdString());
    Path* response = new Path();

    Closure* callback = NewCallback(
      this, &AbsoluteFilePathRequest::handleAbsolutePathResponse, response);

    proxy.absolutePath(&absolutePathRequest, response, callback);
  }

signals:
  void complete(const QString& path);

private:
  QString m_currentDir;
  QString m_path;
  vtkCommunicatorChannel* m_server;
};

void FileDialogModel::absoluteFilePath(const QString& path,
                                       const QObject* requester,
                                       const char* resultSlot)
{

  AbsoluteFilePathRequest* request = new AbsoluteFilePathRequest(
    server(), m_implementation->m_currentPath, path);

  connect(request, SIGNAL(complete(const QString&)), requester, resultSlot);
  connect(request, SIGNAL(complete(const QString&)), this, SLOT(cleanup()));

  request->execute();
}

QStringList FileDialogModel::getFilePaths(const QModelIndex& Index)
{
  if (Index.model() == this)
    return m_implementation->getFilePaths(Index);

  return QStringList();
}

bool FileDialogModel::isHidden(const QModelIndex& Index)
{
  if (Index.model() == this)
    return m_implementation->isHidden(Index);

  return false;
}

bool FileDialogModel::isDir(const QModelIndex& Index)
{
  if (Index.model() == this)
    return m_implementation->isDir(Index);

  return false;
}

void FileDialogModel::cleanup()
{
  sender()->deleteLater();
}

class FileExistsRequest : public QObject
{
  Q_OBJECT
public:
  FileExistsRequest(vtkCommunicatorChannel* server, const QString& path)
    : m_path(path), m_server(server)
  {
  }

  void handleFileExists(Listing* listing)
  {
    if (listing->path().type() == FileDialogModel::SINGLE_FILE)
      emit complete(QString::fromStdString(listing->path().path()), true);
    else if (!QString::fromStdString(listing->path().path()).endsWith(".lnk"))
      execute(QString::fromStdString(listing->path().path() + ".lnk"));
    else
      emit complete(QString::fromStdString(listing->path().path()), false);

    delete listing;
  }

  void execute() { execute(m_path); }

signals:
  void complete(const QString& path, bool exists);

private:
  QString m_path;
  vtkCommunicatorChannel* m_server;

  void execute(const QString& filePath)
  {
    if (filePath.isEmpty())
      emit complete(QString(), false);

    RemoteFileSystemService::Proxy proxy(m_server);
    Path path;
    path.set_path(filePath.toStdString());

    Listing* listing = new Listing();
    Closure* callback =
      NewCallback(this, &FileExistsRequest::handleFileExists, listing);

    proxy.ls(&path, listing, callback);
  }
};

void FileDialogModel::fileExists(const QString& file, const QObject* requester,
                                 const char* resultSlot)
{
  QString filePath = m_implementation->cleanPath(file);

  FileExistsRequest* request = new FileExistsRequest(server(), file);

  connect(request, SIGNAL(complete(const QString&, bool)), requester,
          resultSlot);
  connect(request, SIGNAL(complete(const QString&, bool)), this,
          SLOT(cleanup()));

  request->execute();
}

class DirExistsRequest : public QObject
{
  Q_OBJECT
public:
  DirExistsRequest(vtkCommunicatorChannel* server, const QString& path)
    : m_path(path), m_server(server)
  {
  }

  void handleDirExists(Listing* listing)
  {
    if (FileDialogModel::isDirectory(
          static_cast<FileDialogModel::FileType>(listing->path().type())))
      emit complete(QString::fromStdString(listing->path().path()), true);
    else if (!FileDialogModel::isFile(static_cast<FileDialogModel::FileType>(
               listing->path().type())) &&
             !QString::fromStdString(listing->path().path()).endsWith(".lnk"))
      execute(QString::fromStdString(listing->path().path() + ".lnk"));
    else
      emit complete(QString::fromStdString(listing->path().path()), false);

    delete listing;
  }

  void execute() { execute(m_path); }

signals:
  void complete(const QString& path, bool exists);

private:
  QString m_path;
  vtkCommunicatorChannel* m_server;

  void execute(const QString& dirPath)
  {
    if (dirPath.isEmpty())
      emit complete(QString(), false);

    RemoteFileSystemService::Proxy proxy(m_server);
    Path path;
    path.set_path(dirPath.toStdString());

    Listing* listing = new Listing();
    Closure* callback =
      NewCallback(this, &DirExistsRequest::handleDirExists, listing);

    proxy.ls(&path, listing, callback);
  }
};

void FileDialogModel::dirExists(const QString& path, const QObject* requester,
                                const char* resultSlot)
{
  QString dirPath = m_implementation->cleanPath(path);

  DirExistsRequest* request = new DirExistsRequest(server(), dirPath);

  connect(request, SIGNAL(complete(const QString&, bool)), requester,
          resultSlot);
  connect(request, SIGNAL(complete(const QString&, bool)), this,
          SLOT(cleanup()));

  request->execute();
}

QChar FileDialogModel::separator() const
{
  return m_implementation->m_separator;
}

int FileDialogModel::columnCount(const QModelIndex& idx) const
{
  const FileDialogModelFileInfo* file = m_implementation->infoForIndex(idx);

  if (!file)
    // should never get here anyway
    return 1;

  return file->group().size() + 1;
}

QVariant FileDialogModel::data(const QModelIndex& idx, int role) const
{

  const FileDialogModelFileInfo* file;

  if (idx.column() == 0)
    file = m_implementation->infoForIndex(idx);
  else
    file = m_implementation->infoForIndex(idx.parent());

  if (!file)
    // should never get here anyway
    return QVariant();

  if (role == Qt::DisplayRole || role == Qt::EditRole) {
    if (idx.column() == 0)
      return file->label();
    else if (idx.column() <= file->group().size())
      return file->group().at(idx.column() - 1).label();
  } else if (role == Qt::UserRole) {
    if (idx.column() == 0)
      return file->filePath();
    else if (idx.column() <= file->group().size())
      return file->group().at(idx.column() - 1).filePath();
  } else if (role == Qt::DecorationRole && idx.column() == 0)
    return Icons()->icon(file->type());

  return QVariant();
}

QModelIndex FileDialogModel::index(int row, int column,
                                   const QModelIndex& p) const
{
  if (!p.isValid())
    return createIndex(row, column);

  if (p.row() >= 0 && p.row() < m_implementation->m_fileList.size() &&
      nullptr == p.internalPointer()) {
    FileDialogModelFileInfo* fi = &m_implementation->m_fileList[p.row()];
    return createIndex(row, column, fi);
  }

  return QModelIndex();
}

QModelIndex FileDialogModel::parent(const QModelIndex& idx) const
{
  if (!idx.isValid() || !idx.internalPointer())
    return QModelIndex();

  const FileDialogModelFileInfo* ptr =
    reinterpret_cast<FileDialogModelFileInfo*>(idx.internalPointer());
  int row = ptr - &m_implementation->m_fileList.first();
  return createIndex(row, idx.column());
}

int FileDialogModel::rowCount(const QModelIndex& idx) const
{
  if (!idx.isValid())
    return m_implementation->m_fileList.size();

  if (nullptr == idx.internalPointer() && idx.row() >= 0 &&
      idx.row() < m_implementation->m_fileList.size())
    return m_implementation->m_fileList[idx.row()].group().size();

  return 0;
}

bool FileDialogModel::hasChildren(const QModelIndex& idx) const
{
  if (!idx.isValid())
    return true;

  if (nullptr == idx.internalPointer() && idx.row() >= 0 &&
      idx.row() < m_implementation->m_fileList.size())
    return m_implementation->m_fileList[idx.row()].isGroup();

  return false;
}

QVariant FileDialogModel::headerData(int section, Qt::Orientation,
                                     int role) const
{
  switch (role) {
    case Qt::DisplayRole:
      switch (section) {
        case 0:
          return tr("Filename");
      }
  }

  return QVariant();
}

Qt::ItemFlags FileDialogModel::flags(const QModelIndex& idx) const
{
  Qt::ItemFlags ret = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
  const FileDialogModelFileInfo* file = m_implementation->infoForIndex(idx);
  if (file && !file->isGroup())
    ret |= Qt::ItemIsEditable;

  return ret;
}

bool FileDialogModel::isDirectory(FileDialogModel::FileType t)
{
  return t == DIRECTORY || t == DIRECTORY_LINK || t == DRIVE ||
         t == NETWORK_ROOT || t == NETWORK_DOMAIN || t == NETWORK_SERVER ||
         t == NETWORK_SHARE;
}

bool FileDialogModel::isFile(FileType t)
{
  return t == SINGLE_FILE || t == SINGLE_FILE_LINK;
}

#include "filedialogmodel.moc"
