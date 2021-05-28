/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molequeuemanager.h"

namespace Avogadro {
namespace MoleQueue {

MoleQueueManager* MoleQueueManager::m_instance = nullptr;

MoleQueueManager::MoleQueueManager(QObject* parent_)
  : QObject(parent_), m_client(this), m_queueModel(this)
{
  connect(&m_client, SIGNAL(queueListReceived(QJsonObject)),
          SLOT(updateQueueModel(QJsonObject)));
}

MoleQueueManager::~MoleQueueManager()
{
}

MoleQueueManager& MoleQueueManager::instance()
{
  return m_instance ? *m_instance : *(m_instance = new MoleQueueManager());
}

bool MoleQueueManager::connectIfNeeded()
{
  return m_client.isConnected() || m_client.connectToServer();
}

Client& MoleQueueManager::client()
{
  return m_client;
}

const Client& MoleQueueManager::client() const
{
  return m_client;
}

MoleQueueQueueListModel& MoleQueueManager::queueListModel()
{
  return m_queueModel;
}

bool MoleQueueManager::requestQueueList()
{
  return m_client.isConnected() && m_client.requestQueueList() >= 0;
}

void MoleQueueManager::updateQueueModel(const QJsonObject& json)
{
  QList<QString> queueList;
  QList<QStringList> programList;
  foreach (const QString& queue, json.keys()) {
    queueList.append(queue);
    programList.append(QStringList());
    QStringList& progs = programList.back();
    foreach (const QJsonValue& program, json.value(queue).toArray()) {
      if (program.isString())
        progs << program.toString();
    }
  }
  m_queueModel.setQueueList(queueList, programList);
  emit queueListUpdated();
}

} // namespace MoleQueue
} // namespace Avogadro
