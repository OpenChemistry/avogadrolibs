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

#ifndef AVOGADRO_QTPLUGINS_FILEDIALOGMODEL_H
#define AVOGADRO_QTPLUGINS_FILEDIALOGMODEL_H

#include <QAbstractItemModel>
#include <QFileIconProvider>
#include <QObject>

class vtkProcessModule;
class QModelIndex;

namespace ProtoCall {
namespace Runtime {
class RpcChannel;
class vtkCommunicatorChannel;
}
}

class Listing;
class Path;

/**
 * @class FileDialogModel filedialogmodel.h
 * <avogadro/qtplugins/clientserver/filedialogmodel.h>
 * @brief Remote file dialog model
 */
class FileDialogModel : public QAbstractItemModel
{
  typedef QAbstractItemModel base;

  Q_OBJECT

public:
  enum FileType
  {
    INVALID = 0,
    SINGLE_FILE,
    SINGLE_FILE_LINK,
    DIRECTORY,
    DIRECTORY_LINK,
    FILE_GROUP,
    DRIVE,
    NETWORK_ROOT,
    NETWORK_DOMAIN,
    NETWORK_SERVER,
    NETWORK_SHARE
  };

  FileDialogModel(ProtoCall::Runtime::vtkCommunicatorChannel* server,
                  QObject* Parent = nullptr);
  ~FileDialogModel();

  /// Sets the path that the file dialog will display
  void setCurrentPath(const QString&);

  /// Returns the path to the file dialog will display
  QString getCurrentPath();

  /// Return true if the file at the index is hidden
  bool isHidden(const QModelIndex&);

  /// Return true if the given row is a directory
  bool isDir(const QModelIndex&);

  // Creates a directory. "dirName" can be relative or absolute path
  bool mkdir(const QString& dirname);

  // Removes a directory. "dirName" can be relative or absolute path
  bool rmdir(const QString& dirname);

  // Renames a directory or file.
  bool rename(const QString& oldname, const QString& newname);

  /// Returns whether the file exists
  /// also returns the full path, which could be a resolved shortcut
  void fileExists(const QString& file, const QObject* requestor,
                  const char* resultSlot);

  /// Returns whether a directory exists
  /// also returns the full path, which could be a resolved shortcut
  void dirExists(const QString& dir, const QObject* requestor,
                 const char* resultSlot);

  /// returns the path delimiter, could be \ or / depending on the platform
  /// this model is browsing
  QChar separator() const;

  /// return the absolute path for this file
  void absoluteFilePath(const QString& path, const QObject* requester,
                        const char* resultSlot);

  /// Returns the set of file paths associated with the given row
  /// (a row may represent one-to-many paths if grouping is implemented)
  /// this also resolved symlinks if necessary
  QStringList getFilePaths(const QModelIndex&);

  /// Returns the server that this model is browsing
  ProtoCall::Runtime::vtkCommunicatorChannel* server() const;

  // overloads for QAbstractItemModel

  /// return the number of columns in the model
  int columnCount(const QModelIndex&) const;
  /// return the data for an item
  QVariant data(const QModelIndex& idx, int role) const;
  /// return an index from another index
  QModelIndex index(int row, int column, const QModelIndex&) const;
  /// return the parent index of an index
  QModelIndex parent(const QModelIndex&) const;
  /// return the number of rows under a given index
  int rowCount(const QModelIndex&) const;
  /// return whether a given index has children
  bool hasChildren(const QModelIndex& p) const;
  /// returns header data
  QVariant headerData(int section, Qt::Orientation, int role) const;
  /// returns flags for item
  Qt::ItemFlags flags(const QModelIndex& idx) const;

  static bool isDirectory(FileDialogModel::FileType type);
  static bool isFile(FileDialogModel::FileType type);

signals:
  void fileExistsComplete(const QString& path, bool exists);
  void dirExistsComplete(const QString& path, bool exits);
  void absoluteFilePathComplete(const QString& path);

private:
  class Private;
  Private* const m_implementation;

  void handleFileExists(Listing* listing);
  void handleDirExists(Listing* listing);
  void handleAbsolutePathResponse(Path* response);

private slots:
  void cleanup();
};

class FileDialogModelIconProvider : protected QFileIconProvider
{
public:
  enum IconType
  {
    Computer,
    Drive,
    Folder,
    File,
    FolderLink,
    FileLink,
    NetworkFolder
  };
  FileDialogModelIconProvider();
  QIcon icon(IconType t) const;
  QIcon icon(FileDialogModel::FileType f) const;

protected:
  QIcon icon(const QFileInfo& info) const;
  QIcon icon(QFileIconProvider::IconType ico) const;

  QIcon m_folderLinkIcon;
  QIcon m_fileLinkIcon;
};

#endif
