/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_MOLEQUEUE_CLIENT_H
#define AVOGADRO_MOLEQUEUE_CLIENT_H

#include "avogadromolequeueexport.h"

#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include <QtCore/QObject>
#include <QtCore/QRegExp>
#include <QtCore/QHash>

namespace Avogadro {
namespace MoleQueue {

class JsonRpcClient;
class JobObject;

/**
 * @class Client client.h <molequeue/client/client.h>
 * @brief The Client class is used by clients to submit jobs to a running
 * MoleQueue server.
 * @author Marcus D. Hanwell
 *
 * Provides a simple Qt C++ API to use the MoleQueue JSON-RPC calls to submit
 * and query the state of submitted jobs.
 */

class AVOGADROMOLEQUEUE_EXPORT Client : public QObject
{
  Q_OBJECT

public:
  explicit Client(QObject *parent_ = nullptr);
  ~Client();

  /**
   * Query if the client is connected to a server.
   * @return True if connected, false if not.
   */
  bool isConnected() const;

public slots:
  /**
   * Connect to the server.
   * @param serverName Name of the socket to connect to, the default of
   * "MoleQueue" is usually correct when connecting to the running MoleQueue.
   */
  bool connectToServer(const QString &serverName = "MoleQueue");

  /**
   * Request the list of queues and programs from the server. The signal
   * queueListReceived() will be emitted once this has been received.
   * @return The local ID of the job submission request.
   */
  int requestQueueList();

  /**
   * Submit a job to MoleQueue. If the returned local ID is retained the signal
   * for a job submission will provide the MoleQueue ID along with the local ID.
   * @param job The job specification to be submitted to MoleQueue.
   * @return The local ID of the job submission request.
   */
  int submitJob(const JobObject &job);

  /**
   * Request information about a job. You should supply the MoleQueue ID that
   * was received in response to a job submission.
   * @param moleQueueId The MoleQueue ID for the job.
   * @return The local ID of the job submission request.
   */
  int lookupJob(unsigned int moleQueueId);

  /**
   * Cancel a job that was submitted.
   * @param moleQueueId The MoleQueue ID for the job.
   * @return The local ID of the job submission request.
   */
  int cancelJob(unsigned int moleQueueId);

  /**
   * Register an executable file handler with MoleQueue.
   * @param name GUI name of the file handler.
   * @param executable Executable to call with the filename as the first
   * argument. If the full path to the exectuble is not specified, it must be
   * in the user's $PATH.
   * @param filePatterns A list of QRegExp objects that the handler can open.
   * The QRegExp objects must use RegExp, RegExp2, WildCard, or WildCardUnix
   * pattern syntax, else they will be ignored.
   * @return The local ID of the request.
   * @note The executable is expected to use the following calling convention
   * to open files:
~~~
executable /absolute/path/to/selected/fileName
~~~
   */
  int registerOpenWith(const QString &name, const QString &executable,
                       const QList<QRegExp> &filePatterns);

  /**
   * Register a JSON-RPC 2.0 local socket file handler with MoleQueue.
   * @param name GUI name of the file handler.
   * @param rpcServer Name of the local socket that the server is listening on.
   * @param rpcMethod JSON-RPC 2.0 request method to use.
   * @param filePatterns A list of QRegExp objects that the handler can open.
   * The QRegExp objects must use RegExp, RegExp2, WildCard, or WildCardUnix
   * pattern syntax, else they will be ignored.
   * @return The local ID of the request.
   * @note The following JSON-RPC 2.0 request is sent to the server when the
   * handler is activated:
~~~
{
    "jsonrpc": "2.0",
    "method": "<rpcMethod>",
    "params": {
        "fileName": "/absolute/path/to/selected/fileName"
        }
    },
    "id": "XXX"
}
~~~
   * where <rpcMethod> is replaced by the @a rpcMethod argument.
   */
  int registerOpenWith(const QString &name,
                       const QString &rpcServer, const QString &rpcMethod,
                       const QList<QRegExp> &filePatterns);

  /**
   * @brief Request a list of all file handler names.
   * @return The local ID of the request.
   */
  int listOpenWithNames();

  /**
   * @brief Unregister the indicated file handler from the molequeue server.
   * @param handlerName Name of the file handler to remove.
   * @return The local ID of the request.
   * @sa listOpenWithNames
   */
  int unregisterOpenWith(const QString &handlerName);

  /**
   * @brief flush Flush all pending messages to the server.
   * @warning This should not need to be called if used in an event loop, as Qt
   * will start writing to the socket as soon as control returns to the event
   * loop.
   */
  void flush();

signals:
  /**
   * Emitted when the connection state changes.
   */
  void connectionStateChanged();

  /**
   * Emitted when the remote queue list is received. This gives a list of lists,
   * the primary key is the queue name, and that contains a list of available
   * programs for each queue.
   * @param queues A JSON object containing the names of the queues and the
   * programs each queue have available.
   */
  void queueListReceived(QJsonObject queues);

  /**
   * Emitted when the job request response is received.
   * @param localId The local ID the job submission response is in reply to.
   * @param moleQueueId The remote MoleQueue ID for the job submission (can be
   * used to perform further actions on the job).
   */
  void submitJobResponse(int localId, unsigned int moleQueueId);

  /**
   * Emitted when a job lookup response is received.
   * @param localId The local ID the job submission response is in reply to.
   * @param jobInfo A Json object containing all available job information.
   */
  void lookupJobResponse(int localId, QJsonObject jobInfo);

  /**
   * Emitted when a job is successfully cancelled.
   */
  void cancelJobResponse(unsigned int moleQueueId);

  /**
   * Emitted when the job state changes.
   */
  void jobStateChanged(unsigned int moleQueueId, QString oldState,
                       QString newState);

  /**
   * Emitted when a successful registerOpenWith response is received.
   */
  void registerOpenWithResponse(int localId);

  /**
   * Emitted when a successful listOpenWithNames response is received.
   */
  void listOpenWithNamesResponse(int localId, QJsonArray handlerNames);

  /**
   * Emitted when a successful unregisterOpenWith response is received.
   */
  void unregisterOpenWithResponse(int localId);

  /**
   * Emitted when an error response is received.
   */
  void errorReceived(int localId, int errorCode, QString errorMessage,
                     QJsonValue errorData);

protected slots:
  /** Parse the response object and emit the appropriate signal(s). */
  void processResult(const QJsonObject &response);

  /** Parse a notification object and emit the appropriate signal(s). */
  void processNotification(const QJsonObject &notification);

  /** Parse an error object and emit the appropriate signal(s). */
  void processError(const QJsonObject &notification);

protected:
  enum MessageType {
    Invalid = -1,
    ListQueues,
    SubmitJob,
    CancelJob,
    LookupJob,
    RegisterOpenWith,
    ListOpenWithNames,
    UnregisterOpenWith
  };

  JsonRpcClient *m_jsonRpcClient;
  QHash<unsigned int, MessageType> m_requests;

private:
  QJsonObject buildRegisterOpenWithRequest(const QString &name,
                                           const QList<QRegExp> &filePatterns,
                                           const QJsonObject &handlerMethod);
};

} // End namespace MoleQueue
} // End namespace Avogadro

#endif // AVOGADRO_MOLEQUEUE_CLIENT_H
