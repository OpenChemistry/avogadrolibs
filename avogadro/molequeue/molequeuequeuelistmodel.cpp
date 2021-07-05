/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molequeuequeuelistmodel.h"

#include <QtCore/QDebug>

#include <limits>

namespace Avogadro {
namespace MoleQueue {

namespace {
// Internal id used for queue model indices
static const quint32 QueueInternalId(std::numeric_limits<quint32>::max());

// Internal id used for invalid indices
static const quint32 InvalidInternalId(std::numeric_limits<quint32>::max() - 1);

// Maximum assignable internal id. Must be last:
static const quint32 MaxInternalId(std::numeric_limits<quint32>::max() - 2);
}

MoleQueueQueueListModel::MoleQueueQueueListModel(QObject* parent_)
  : QAbstractItemModel(parent_), m_uidCounter(0)
{
}

MoleQueueQueueListModel::~MoleQueueQueueListModel()
{
}

void MoleQueueQueueListModel::setQueueList(QList<QString> queueList,
                                           QList<QStringList> programList)
{
  const int numQueues = queueList.size();
  if (numQueues != programList.size()) {
    qWarning() << "Error setting molequeue queuelist data in model: "
                  "number of queues does not match size of program table.";
    return;
  }

  // Sync our data structures with the arguments:
  int newInd = 0;
  int oldInd = 0;
  while (newInd < queueList.size() && oldInd < m_queueList.size()) {
    const QString& newQueue = queueList[newInd];
    const QString& oldQueue = m_queueList[oldInd];
    if (newQueue < oldQueue) {
      const QStringList& newProgs = programList[newInd];
      insertQueue(oldInd, newQueue, newProgs);
      ++oldInd;
      ++newInd;
    } else if (oldQueue < newQueue) {
      removeQueue(oldInd);
    } else { // newQueue == oldQueue
      const QStringList& newProgs = programList[newInd];
      mergeQueue(oldInd, newProgs);
      ++oldInd;
      ++newInd;
    }
  }
  // Add any remaining new queues
  for (; newInd < queueList.size(); ++newInd, ++oldInd)
    insertQueue(m_queueList.size(), queueList[newInd], programList[newInd]);
  // or remove any stale old queues.
  while (oldInd < m_queueList.size())
    removeQueue(oldInd);
}

QStringList MoleQueueQueueListModel::queues() const
{
  return m_queueList;
}

QStringList MoleQueueQueueListModel::programs(const QString& queue) const
{
  int ind = m_queueList.indexOf(queue);
  return ind >= 0 ? m_programList[ind] : QStringList();
}

QModelIndexList MoleQueueQueueListModel::findQueueIndices(
  const QString& filter) const
{
  return match(index(0, 0), Qt::DisplayRole, filter, -1, Qt::MatchContains);
}

QModelIndexList MoleQueueQueueListModel::findProgramIndices(
  const QString& programFilter, const QString& queueFilter) const
{
  QModelIndexList result;
  foreach (const QModelIndex& idx, findQueueIndices(queueFilter)) {
    result << match(index(0, 0, idx), Qt::DisplayRole, programFilter, -1,
                    Qt::MatchContains);
  }
  return result;
}

bool MoleQueueQueueListModel::lookupProgram(const QModelIndex& idx,
                                            QString& queueName,
                                            QString& programName) const
{
  QVariant resultVariant = data(idx, QueueProgramRole);
  if (resultVariant.type() == QVariant::StringList) {
    QStringList resultList(resultVariant.toStringList());
    if (resultList.size() == 2) {
      queueName = resultList[0];
      programName = resultList[1];
      return true;
    }
  }
  queueName.clear();
  programName.clear();
  return false;
}

QVariant MoleQueueQueueListModel::data(const QModelIndex& idx, int role) const
{
  if (!idx.isValid() || (role != Qt::DisplayRole && role != QueueProgramRole)) {
    return QVariant();
  }

  if (isQueueIndex(idx)) {
    if (role == Qt::DisplayRole) {
      return m_queueList[idx.row()];
    }
  } else {
    const int queueIndex(idx.parent().row());
    if (queueIndex < m_queueList.size()) {
      const QStringList& progs(m_programList[queueIndex]);
      if (idx.row() < progs.size()) {
        const QString& prog(progs[idx.row()]);
        switch (role) {
          case Qt::DisplayRole:
            return prog;
          case QueueProgramRole: {
            QStringList result = m_uidLookup.value(
              static_cast<quint32>(idx.internalId()), QStringList());
            if (result.size() == 2)
              return result;
            break;
          }
          default:
            break;
        }
      }
    }
  }
  return QVariant();
}

Qt::ItemFlags MoleQueueQueueListModel::flags(const QModelIndex& idx) const
{
  if (!idx.isValid())
    return Qt::NoItemFlags;

  if (isQueueIndex(idx))
    return Qt::ItemIsEnabled;
  else
    return Qt::ItemIsSelectable | Qt::ItemIsEnabled;
}

QVariant MoleQueueQueueListModel::headerData(int, Qt::Orientation, int) const
{
  return QVariant();
}

QModelIndex MoleQueueQueueListModel::index(int row, int column,
                                           const QModelIndex& parent_) const
{
  if (!hasIndex(row, column, parent_))
    return QModelIndex();

  // Queue Index -- parent is invalid.
  if (!parent_.isValid() && row < m_queueList.size() && column == 0) {
    return createIndex(row, column, QueueInternalId);
  }
  // Program index
  else if (isQueueIndex(parent_)) {
    const QStringList& progs(m_programList[parent_.row()]);
    if (row < progs.size() && column == 0) {
      const QString& queue(m_queueList[parent_.row()]);
      const QString& prog(progs[row]);
      QStringList val = QStringList() << queue << prog;
      quint32 key = m_uidLookup.key(val, InvalidInternalId);
      if (key != InvalidInternalId)
        return createIndex(row, column, key);
    }
  }
  // fail.
  return QModelIndex();
}

QModelIndex MoleQueueQueueListModel::parent(const QModelIndex& child) const
{
  if (child.isValid()) {
    const quint32 childId = static_cast<quint32>(child.internalId());

    // Child is queue -- return invalid parent.
    if (childId == QueueInternalId)
      return QModelIndex();

    // Child is program -- lookup and return queue index.
    const int queueRow = programUidToQueueRow(childId);
    if (queueRow >= 0)
      return createIndex(queueRow, 0, QueueInternalId);
  }
  return QModelIndex();
}

int MoleQueueQueueListModel::rowCount(const QModelIndex& parent_) const
{
  // Queue count:
  if (!parent_.isValid())
    return m_queueList.size();
  else if (isQueueIndex(parent_))
    return m_programList[parent_.row()].size();
  return 0;
}

int MoleQueueQueueListModel::columnCount(const QModelIndex& parent_) const
{
  return (!parent_.isValid() || isQueueIndex(parent_)) ? 1 : 0;
}

void MoleQueueQueueListModel::insertQueue(int row, const QString& queue,
                                          const QStringList& progs)
{
  beginInsertRows(QModelIndex(), row, row);
  m_queueList.insert(row, queue);
  m_programList.insert(row, QStringList());
  endInsertRows();

  beginInsertRows(createIndex(row, 0, QueueInternalId), 0, progs.size() - 1);
  m_programList[row] = progs;
  foreach (const QString& progName, progs)
    m_uidLookup.insert(nextUid(), QStringList() << queue << progName);
  endInsertRows();
}

void MoleQueueQueueListModel::removeQueue(int row)
{
  const QString queue(m_queueList[row]);
  QStringList& progs = m_programList[row];

  beginRemoveRows(createIndex(row, 0, QueueInternalId), 0, progs.size() - 1);
  foreach (const QString& prog, progs)
    m_uidLookup.remove(lookupUid(queue, prog));
  progs.clear();
  endRemoveRows();

  beginRemoveRows(QModelIndex(), row, row);
  m_queueList.removeAt(row);
  m_programList.removeAt(row);
  endRemoveRows();
}

void MoleQueueQueueListModel::mergeQueue(int row, const QStringList& newProgs)
{
  QStringList& oldProgs(m_programList[row]);

  int oldInd = 0;
  int newInd = 0;
  while (oldInd < oldProgs.size() && newInd < newProgs.size()) {
    const QString& oldProg(oldProgs[oldInd]);
    const QString& newProg(newProgs[newInd]);
    if (newProg < oldProg) {
      insertProgram(row, oldInd, newProg);
      ++newInd;
      ++oldInd;
    } else if (oldProg < newProg) {
      removeProgram(row, oldInd);
    } else { // Program exists
      ++newInd;
      ++oldInd;
    }
  }

  // Add any remaining new programs
  for (; newInd < newProgs.size(); ++newInd, ++oldInd)
    insertProgram(row, m_programList[row].size(), newProgs[newInd]);

  // Or remove any old programs.
  while (oldInd < m_programList[row].size())
    removeProgram(row, oldInd);
}

void MoleQueueQueueListModel::insertProgram(int queueRow, int progRow,
                                            const QString& progName)
{
  beginInsertRows(createIndex(queueRow, 0, QueueInternalId), progRow, progRow);
  m_programList[queueRow].insert(progRow, progName);
  m_uidLookup.insert(nextUid(), QStringList() << m_queueList[queueRow]
                                              << progName);
  endInsertRows();
}

void MoleQueueQueueListModel::removeProgram(int queueRow, int progRow)
{
  beginRemoveRows(createIndex(queueRow, 0, QueueInternalId), progRow, progRow);
  m_uidLookup.remove(lookupUid(queueRow, progRow));
  m_programList[queueRow].removeAt(progRow);
  endRemoveRows();
}

bool MoleQueueQueueListModel::isQueueIndex(const QModelIndex& i) const
{
  if (i.isValid() && static_cast<quint32>(i.internalId()) == QueueInternalId &&
      i.row() < m_queueList.size() && i.column() == 0) {
    return true;
  }
  return false;
}

bool MoleQueueQueueListModel::isProgramIndex(const QModelIndex& i) const
{
  return i.isValid() &&
         m_uidLookup.contains(static_cast<quint32>(i.internalId()));
}

quint32 MoleQueueQueueListModel::lookupUid(const QString& queue,
                                           const QString& prog)
{
  return m_uidLookup.key(QStringList() << queue << prog, InvalidInternalId);
}

quint32 MoleQueueQueueListModel::lookupUid(const int queueRow,
                                           const int progRow)
{
  if (queueRow < m_queueList.size()) {
    QStringList& progs = m_programList[queueRow];
    if (progRow < progs.size())
      return lookupUid(m_queueList[queueRow], progs[progRow]);
  }
  return InvalidInternalId;
}

int MoleQueueQueueListModel::programUidToQueueRow(quint32 uid) const
{
  const QStringList val(m_uidLookup.value(uid, QStringList()));
  if (val.size() == 2) {
    const QString& queue = val[0];
    const int queueRow = m_queueList.indexOf(queue);
    if (queueRow >= 0)
      return queueRow;
  }
  return -1;
}

quint32 MoleQueueQueueListModel::nextUid()
{
  if (m_uidCounter++ >= MaxInternalId)
    m_uidCounter = 0;
  return m_uidCounter;
}

} // namespace MoleQueue
} // namespace Avogadro
