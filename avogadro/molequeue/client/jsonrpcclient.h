/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_MOLEQUEUE_JSONRPCCLIENT_H
#define AVOGADRO_MOLEQUEUE_JSONRPCCLIENT_H

#include "avogadromolequeueexport.h"

#include <QtCore/QJsonObject>
#include <QtCore/QObject>

class QLocalSocket;

namespace Avogadro {
namespace MoleQueue {

/**
 * @class JsonRpcClient jsonrpcclient.h <molequeue/client/jsonrpcclient.h>
 * @brief The JsonRpcClient class is used by clients to submit calls to an RPC
 * server using JSON-RPC 2.0.
 * @author Marcus D. Hanwell
 *
 * Provides a simple Qt C++ API to make JSON-RPC 2.0 calls to an RPC server. To
 * create a client connection and call a method the following should be done:
 *
 @code
 #include <molequeue/client/jsonrpcclient.h>

 MoleQueue::JsonRpcClient *client = new MoleQueue::JsonRpcClient(this);
 client->connectToServer("MyRpcServer");
 QJsonObject request(client->emptyRequest());
 request["method"] = QLatin1String("listQueues");
 client->sendRequest(request);
 @endcode
 *
 * You should connect to the appropriate signals in order to act on results,
 * notifications and errors received in response to requests set using the
 * client connection.
 */

class AVOGADROMOLEQUEUE_EXPORT JsonRpcClient : public QObject
{
  Q_OBJECT

public:
  explicit JsonRpcClient(QObject *parent_ = nullptr);
  ~JsonRpcClient();

  /**
   * Query if the client is connected to a server.
   * @return True if connected, false if not.
   */
  bool isConnected() const;

  /**
   * @return The server name that the client is connected to.
   */
  QString serverName() const;

public slots:
  /**
   * Connect to the server.
   * @param serverName Name of the socket to connect to.
   */
  bool connectToServer(const QString &serverName);

  /**
   * @brief flush Flush all pending messages to the server.
   * @warning This should not need to be called if used in an event loop, as Qt
   * will start writing to the socket as soon as control returns to the event
   * loop.
   */
  void flush();

  /**
   * Use this function to construct an empty JSON-RPC 2.0 request, with a valid
   * request id, JSON-RPC 2.0 key etc.
   * @return a standard empty JSON-RPC 2.0 packet, the method etc is empty.
   */
  QJsonObject emptyRequest();

  /**
   * Send the Json request to the RPC server.
   * @param request The JSON-RPC 2.0 request object.
   * @return True on success, false on failure.
   */
  bool sendRequest(const QJsonObject &request);

protected slots:
  /**
   * Read incoming packets of data from the server.
   */
  void readPacket(const QByteArray message);

  /**
   * Read incoming data, interpret JSON stream.
   */
  void readSocket();

signals:
  /**
   * Emitted when the connection state changes.
   */
  void connectionStateChanged();

  /**
   * Emitted when a result is received.
   */
  void resultReceived(QJsonObject message);

  /**
   * Emitted when a notification is received.
   */
  void notificationReceived(QJsonObject message);

  /**
   * Emitted when an error response is received.
   */
  void errorReceived(QJsonObject message);

  /**
   * Emitted when a bad packet was received that the client could not parse.
   */
  void badPacketReceived(QString error);

  /**
   * Emitted when a new packet of data is received. This is handled internally,
   * other classes should listen to resultReceived, notificationReceived,
   * errorReceived, and badPacketReceived.
   */
  void newPacket(const QByteArray &packet);

protected:
  unsigned int m_packetCounter;
  QLocalSocket *m_socket;
};

} // End namespace MoleQueue
} // End namespace Avogadro

#endif // AVOGADRO_MOLEQUEUE_JSONRPCCLIENT_H
