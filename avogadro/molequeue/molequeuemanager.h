/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_MOLEQUEUE_MOLEQUEUEMANAGER_H
#define AVOGADRO_MOLEQUEUE_MOLEQUEUEMANAGER_H

#include <QtCore/QObject>

#include "molequeuequeuelistmodel.h"

#include <avogadro/core/avogadrocore.h>

#include "client/client.h"

namespace Avogadro {
namespace MoleQueue {

/**
 * @class MoleQueueManager molequeuemanager.h
 * <avogadro/molequeue/molequeuemanager.h>
 * @brief The MoleQueueManager class provides access to a MoleQueue server.
 *
 * This singleton class provides access to a single MoleQueue::Client instance
 * that can be used to communicate with the server. The available queues and
 * programs are cached in a MoleQueueQueueListModel (queueListModel()). The
 * connectIfNeeded convenience function can be used to ensure that the client
 * is connected before use.
 */
class AVOGADROMOLEQUEUE_EXPORT MoleQueueManager : public QObject
{
  Q_OBJECT
public:
  explicit MoleQueueManager(QObject* parent_ = nullptr);
  ~MoleQueueManager() override;

  /**
   * @return The singleton instance.
   */
  static MoleQueueManager& instance();

  /**
   * Test if the client is connected, and if not, attempt a connection.
   * @return True if the client is already connected or a new connection has
   * been successfully created. False if the new connection failed.
   */
  bool connectIfNeeded();

  /**
   * @return A reference to the managed Client instance.
   * @{
   */
  Client& client();
  const Client& client() const;
  /** @} */

  /**
   * @return A QAbstractItemModel subclass representing the queue/program tree.
   */
  MoleQueueQueueListModel& queueListModel();

public slots:
  /**
   * Request that the cached queue list is updated.
   * @return True if the request is send successfully.
   */
  bool requestQueueList();

signals:
  /**
   * Emitted when the internal queue list is updated.
   */
  void queueListUpdated();

private slots:
  void updateQueueModel(const QJsonObject& queueList);

private:
  static MoleQueueManager* m_instance;
  Client m_client;
  MoleQueueQueueListModel m_queueModel;
};

} // namespace MoleQueue
} // namespace Avogadro

#endif // AVOGADRO_MOLEQUEUE_MOLEQUEUEMANAGER_H
