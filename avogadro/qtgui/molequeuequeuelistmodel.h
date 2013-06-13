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

#ifndef AVOGADRO_QTGUI_MOLEQUEUEQUEUELISTMODEL_H
#define AVOGADRO_QTGUI_MOLEQUEUEQUEUELISTMODEL_H

#include <QtCore/QAbstractItemModel>
#include "avogadroqtguiexport.h"

#include <QtCore/QStringList>

namespace Avogadro {
namespace QtGui {
class MoleQueueManager;

/**
 * @class MoleQueueQueueListModel molequeuequeuelistmodel.h
 * <avogadro/qtgui/molequeuequeuelistmodel.h>
 * @brief The MoleQueueQueueListModel class is Qt item model representing the
 * tree of available queues and programs in a running MoleQueue process.
 *
 * This class provides access to the available MoleQueue queues and models in
 * a convenient tree item model. Resources can be queried directly using the
 * queues() and programs() methods, or this item model may be used with a Qt
 * model view class, such a QTreeView.
 *
 * QModelIndex objects that match a queue or program node may be found using the
 * findQueueIndices() and findProgramIndices() methods. A program model index
 * may be translated into queue and program strings using the lookupProgram()
 * method.
 *
 * An instance of this class is obtained by calling
 * MoleQueueManager::instance().queueListModel(), and can be updated by calling
 * MoleQueueManager::instance().requestQueueList() and waiting for the
 * MoleQueueManager::queueListUpdated() signal.
 */
class AVOGADROQTGUI_EXPORT MoleQueueQueueListModel : public QAbstractItemModel
{
  Q_OBJECT
public:
  ~MoleQueueQueueListModel();

  /**
   * @return A list of the available queues.
   */
  QStringList queues() const;

  /**
   * @return A list of programs belonging to @a queue.
   */
  QStringList programs(const QString &queue) const;

  /**
   * @return A QModelIndexList containing indices for queues that contain the
   * string @a filter. Matches are case-insensitive.
   */
  QModelIndexList findQueueIndices(const QString &filter = QString()) const;

  /**
   * @return A QModelIndexList containing indices for programs that contain the
   * string @a programFilter and belong to queues that contain @a queueFilter.
   * Matches are case-insensitive.
   */
  QModelIndexList findProgramIndices(
      const QString &programFilter = QString(),
      const QString &queueFilter = QString()) const;

  /**
   * Translate a QModelIndex for a program node into queue and program strings.
   * @param idx The model index.
   * @param queueName String reference to be overwritten with the queue name.
   * @param programName String reference to be overwritten with the queue name.
   * @return True if the index matched a program node, false otherwise.
   */
  bool lookupProgram(const QModelIndex &idx,
                     QString &queueName, QString &programName) const;

  // QAbstractItemModel virtuals
  QVariant data(const QModelIndex &idx, int role) const;
  Qt::ItemFlags flags(const QModelIndex &idx = QModelIndex()) const;
  QVariant headerData(int section, Qt::Orientation orientation, int role) const;
  QModelIndex index(int row, int column,
                    const QModelIndex &parent_ = QModelIndex()) const;
  QModelIndex parent(const QModelIndex &child) const;
  int rowCount(const QModelIndex &parent_ = QModelIndex()) const;
  int columnCount(const QModelIndex &parent_ = QModelIndex()) const;

protected:
  friend class MoleQueueManager;

  /**
   * Protected constructor. Keeps objects isolated to MoleQueueManager ivars.
   */
  explicit MoleQueueQueueListModel(QObject *parent_ = 0);

  /**
   * Used to retrieve a QStringList with [queueName, programName] from data()
   * given a program model index.
   */
  enum { QueueProgramRole = Qt::UserRole };

  /**
   * Merge the queue and program lists with the existing model.
   */
  void setQueueList(QList<QString> queueList, QList<QStringList> programList);

private:
  void insertQueue(int row, const QString &queue, const QStringList &progs);
  void removeQueue(int row);
  void mergeQueue(int row, const QStringList &newProgs);
  void insertProgram(int queueRow, int progRow, const QString &progName);
  void removeProgram(int queueRow, int progRow);

  bool isQueueIndex(const QModelIndex &i) const;
  bool isProgramIndex(const QModelIndex &i) const;

  quint32 lookupUid(const QString &queue, const QString &prog);
  quint32 lookupUid(const int queueRow, const int progRow);
  int programUidToQueueRow(quint32 uid) const;

  quint32 nextUid();

  QList<QString> m_queueList;
  QList<QStringList> m_programList;
  // maps program index internal id to [queueName, programName] QStringList
  QMap<quint32, QStringList> m_uidLookup;
  quint32 m_uidCounter;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_MOLEQUEUEQUEUELISTMODEL_H
