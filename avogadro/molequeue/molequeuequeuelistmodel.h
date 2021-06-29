/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_MOLEQUEUE_MOLEQUEUEQUEUELISTMODEL_H
#define AVOGADRO_MOLEQUEUE_MOLEQUEUEQUEUELISTMODEL_H

#include "avogadromolequeueexport.h"
#include <QtCore/QAbstractItemModel>

#include <QtCore/QStringList>

// for gtest unit testing access
class MoleQueueQueueListModelTestBridge;

namespace Avogadro {
namespace MoleQueue {
class MoleQueueManager;

/**
 * @class MoleQueueQueueListModel molequeuequeuelistmodel.h
 * <avogadro/molequeue/molequeuequeuelistmodel.h>
 * @brief The MoleQueueQueueListModel class is Qt item model representing the
 * tree of available queues and programs in a running MoleQueue process.
 *
 * This class provides access to the available MoleQueue queues and programs in
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
class AVOGADROMOLEQUEUE_EXPORT MoleQueueQueueListModel
  : public QAbstractItemModel
{
  Q_OBJECT
public:
  ~MoleQueueQueueListModel() override;

  /**
   * @return A list of the available queues.
   */
  QStringList queues() const;

  /**
   * @return A list of programs belonging to @a queue.
   */
  QStringList programs(const QString& queue) const;

  /**
   * @return A QModelIndexList containing indices for queues that contain the
   * string @a filter. Matches are case-insensitive.
   */
  QModelIndexList findQueueIndices(const QString& filter = QString()) const;

  /**
   * @return A QModelIndexList containing indices for programs that contain the
   * string @a programFilter and belong to queues that contain @a queueFilter.
   * Matches are case-insensitive.
   */
  QModelIndexList findProgramIndices(
    const QString& programFilter = QString(),
    const QString& queueFilter = QString()) const;

  /**
   * Translate a QModelIndex for a program node into queue and program strings.
   * @param idx The model index.
   * @param queueName String reference to be overwritten with the queue name.
   * @param programName String reference to be overwritten with the queue name.
   * @return True if the index matched a program node, false otherwise.
   */
  bool lookupProgram(const QModelIndex& idx, QString& queueName,
                     QString& programName) const;

  // QAbstractItemModel virtuals
  QVariant data(const QModelIndex& idx, int role) const override;
  Qt::ItemFlags flags(const QModelIndex& idx = QModelIndex()) const override;
  QVariant headerData(int section, Qt::Orientation orientation,
                      int role) const override;
  QModelIndex index(int row, int column,
                    const QModelIndex& parent_ = QModelIndex()) const override;
  QModelIndex parent(const QModelIndex& child) const override;
  int rowCount(const QModelIndex& parent_ = QModelIndex()) const override;
  int columnCount(const QModelIndex& parent_ = QModelIndex()) const override;

protected:
  friend class MoleQueueManager;
  friend class ::MoleQueueQueueListModelTestBridge;

  /**
   * Protected constructor. Keeps objects isolated to MoleQueueManager ivars.
   */
  explicit MoleQueueQueueListModel(QObject* parent_ = nullptr);

  /**
   * Used to retrieve a QStringList with [queueName, programName] from data()
   * given a program model index.
   */
  enum
  {
    QueueProgramRole = Qt::UserRole
  };

  /**
   * Merge the queue and program lists with the existing model.
   */
  void setQueueList(QList<QString> queueList, QList<QStringList> programList);

private:
  void insertQueue(int row, const QString& queue, const QStringList& progs);
  void removeQueue(int row);
  void mergeQueue(int row, const QStringList& newProgs);
  void insertProgram(int queueRow, int progRow, const QString& progName);
  void removeProgram(int queueRow, int progRow);

  bool isQueueIndex(const QModelIndex& i) const;
  bool isProgramIndex(const QModelIndex& i) const;

  quint32 lookupUid(const QString& queue, const QString& prog);
  quint32 lookupUid(const int queueRow, const int progRow);
  int programUidToQueueRow(quint32 uid) const;

  quint32 nextUid();

  QList<QString> m_queueList;
  QList<QStringList> m_programList;
  // maps program index internal id to [queueName, programName] QStringList
  QMap<quint32, QStringList> m_uidLookup;
  quint32 m_uidCounter;
};

} // namespace MoleQueue
} // namespace Avogadro

#endif // AVOGADRO_MOLEQUEUE_MOLEQUEUEQUEUELISTMODEL_H
