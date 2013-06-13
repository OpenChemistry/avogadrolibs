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

#ifndef AVOGADRO_QTGUI_MOLEQUEUEPROXY_H
#define AVOGADRO_QTGUI_MOLEQUEUEPROXY_H

#include <QtCore/QObject>

#include <avogadro/qtgui/avogadroqtguiexport.h>
#include <avogadro/qtgui/molequeuequeuelistmodel.h>

#include <avogadro/core/avogadrocore.h>

#include <molequeue/client/client.h>
#include <molequeue/client/job.h>

#include <QtCore/QStringList>
#include <QtCore/QModelIndex>
#include <QtCore/QModelIndexList>

#include <limits>

namespace Avogadro {
namespace QtGui {

/**
 * @class MoleQueueManager molequeuemanager.h
 * <avogadro/qtgui/molequeuemanager.h>
 * @brief The MoleQueueManager class provides access to a MoleQueue server.
 *
 * This singleton class provides access to a single MoleQueue::Client instance
 * that can be used to communicate with the server. The available queues and
 * programs are cached in a MoleQueueQueueListModel (queueListModel()). The
 * connectIfNeeded convenience function can be used to ensure that the client
 * is connected before use.
 */
class AVOGADROQTGUI_EXPORT MoleQueueManager : public QObject
{
  Q_OBJECT
public:
  explicit MoleQueueManager(QObject *parent_ = 0);
  ~MoleQueueManager() AVO_OVERRIDE;

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
   * @return A reference to the managed MoleQueue::Client instance.
   * @{
   */
  MoleQueue::Client& client();
  const MoleQueue::Client& client() const;
  /** @} */

  /**
   * @return A QAbstractItemModel subclass representing the queue/program tree.
   */
  MoleQueueQueueListModel &queueListModel();

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
  void updateQueueModel(const QJsonObject &queueList);

private:
  static MoleQueueManager *m_instance;
  MoleQueue::Client m_client;
  MoleQueueQueueListModel m_queueModel;

};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_MOLEQUEUEPROXY_H
