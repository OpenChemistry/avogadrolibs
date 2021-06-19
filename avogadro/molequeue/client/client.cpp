/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "client.h"

#include "jsonrpcclient.h"
#include "jobobject.h"

#include <QtCore/QJsonDocument>

namespace Avogadro {
namespace MoleQueue {

Client::Client(QObject *parent_) : QObject(parent_), m_jsonRpcClient(nullptr)
{
}

Client::~Client()
{
}

bool Client::isConnected() const
{
  if (!m_jsonRpcClient)
    return false;
  else
    return m_jsonRpcClient->isConnected();
}

bool Client::connectToServer(const QString &serverName)
{
  if (!m_jsonRpcClient) {
    m_jsonRpcClient = new JsonRpcClient(this);
    connect(m_jsonRpcClient, SIGNAL(resultReceived(QJsonObject)),
            SLOT(processResult(QJsonObject)));
    connect(m_jsonRpcClient, SIGNAL(notificationReceived(QJsonObject)),
            SLOT(processNotification(QJsonObject)));
    connect(m_jsonRpcClient, SIGNAL(errorReceived(QJsonObject)),
            SLOT(processError(QJsonObject)));
    connect(m_jsonRpcClient, SIGNAL(connectionStateChanged()),
            SIGNAL(connectionStateChanged()));
  }

  return m_jsonRpcClient->connectToServer(serverName);
}

int Client::requestQueueList()
{
  if (!m_jsonRpcClient)
    return -1;

  QJsonObject packet = m_jsonRpcClient->emptyRequest();
  packet["method"] = QLatin1String("listQueues");
  if (!m_jsonRpcClient->sendRequest(packet))
    return -1;

  int localId = static_cast<int>(packet["id"].toDouble());
  m_requests[localId] = ListQueues;
  return localId;
}

int Client::submitJob(const JobObject &job)
{
  if (!m_jsonRpcClient)
    return -1;

  QJsonObject packet = m_jsonRpcClient->emptyRequest();
  packet["method"] = QLatin1String("submitJob");
  packet["params"] = job.json();
  if (!m_jsonRpcClient->sendRequest(packet))
    return -1;

  int localId = static_cast<int>(packet["id"].toDouble());
  m_requests[localId] = SubmitJob;
  return localId;
}

int Client::lookupJob(unsigned int moleQueueId)
{
  if (!m_jsonRpcClient)
    return -1;

  QJsonObject packet = m_jsonRpcClient->emptyRequest();
  packet["method"] = QLatin1String("lookupJob");
  QJsonObject params;
  params["moleQueueId"] = static_cast<int>(moleQueueId);
  packet["params"] = params;
  if (!m_jsonRpcClient->sendRequest(packet))
    return -1;

  int localId = static_cast<int>(packet["id"].toDouble());
  m_requests[localId] = LookupJob;
  return localId;
}

int Client::cancelJob(unsigned int moleQueueId)
{
  if (!m_jsonRpcClient)
    return -1;

  QJsonObject packet = m_jsonRpcClient->emptyRequest();
  packet["method"] = QLatin1String("cancelJob");
  QJsonObject params;
  params["moleQueueId"] = static_cast<int>(moleQueueId);
  packet["params"] = params;
  if (!m_jsonRpcClient->sendRequest(packet))
    return -1;

  int localId = static_cast<int>(packet["id"].toDouble());
  m_requests[localId] = CancelJob;
  return localId;
}

int Client::registerOpenWith(const QString &name, const QString &executable,
                             const QList<QRegExp> &filePatterns)
{
  if (!m_jsonRpcClient)
    return -1;

  QJsonObject method;
  method["executable"] = executable;

  QJsonObject packet(buildRegisterOpenWithRequest(name, filePatterns, method));

  if (!m_jsonRpcClient->sendRequest(packet))
    return -1;

  int localId = static_cast<int>(packet["id"].toDouble());
  m_requests[localId] = RegisterOpenWith;
  return localId;
}

int Client::registerOpenWith(const QString &name,
                             const QString &rpcServer, const QString &rpcMethod,
                             const QList<QRegExp> &filePatterns)
{
  if (!m_jsonRpcClient)
    return -1;

  QJsonObject method;
  method["rpcServer"] = rpcServer;
  method["rpcMethod"] = rpcMethod;

  QJsonObject packet(buildRegisterOpenWithRequest(name, filePatterns, method));

  if (!m_jsonRpcClient->sendRequest(packet))
    return -1;

  int localId = static_cast<int>(packet["id"].toDouble());
  m_requests[localId] = RegisterOpenWith;
  return localId;
}

int Client::listOpenWithNames()
{
  if (!m_jsonRpcClient)
    return -1;

  QJsonObject packet = m_jsonRpcClient->emptyRequest();
  packet["method"] = QLatin1String("listOpenWithNames");
  if (!m_jsonRpcClient->sendRequest(packet))
    return -1;

  int localId = static_cast<int>(packet["id"].toDouble());
  m_requests[localId] = ListOpenWithNames;
  return localId;
}

int Client::unregisterOpenWith(const QString &handlerName)
{
  if (!m_jsonRpcClient)
    return -1;

  QJsonObject packet = m_jsonRpcClient->emptyRequest();
  packet["method"] = QLatin1String("unregisterOpenWith");
  QJsonObject params;
  params["name"] = handlerName;
  packet["params"] = params;
  if (!m_jsonRpcClient->sendRequest(packet))
    return -1;

  int localId = static_cast<int>(packet["id"].toDouble());
  m_requests[localId] = UnregisterOpenWith;
  return localId;
}

void Client::flush()
{
  if (m_jsonRpcClient)
    m_jsonRpcClient->flush();
}

void Client::processResult(const QJsonObject &response)
{
  if (response["id"] != QJsonValue::Null
      && m_requests.contains(static_cast<int>(response["id"].toDouble()))) {
    int localId = static_cast<int>(response["id"].toDouble());
    switch (m_requests[localId]) {
    case ListQueues:
      emit queueListReceived(response["result"].toObject());
      break;
    case SubmitJob:
      emit submitJobResponse(localId,
                             static_cast<unsigned int>(response["result"]
                             .toObject()["moleQueueId"].toDouble()));
      break;
    case LookupJob:
      emit lookupJobResponse(localId, response["result"].toObject());
      break;
    case CancelJob:
      emit cancelJobResponse(static_cast<unsigned int>(response["result"]
                             .toObject()["moleQueueId"].toDouble()));
      break;
    case RegisterOpenWith:
      emit registerOpenWithResponse(localId);
      break;
    case ListOpenWithNames:
      emit listOpenWithNamesResponse(localId, response["result"].toArray());
      break;
    case UnregisterOpenWith:
      emit unregisterOpenWithResponse(localId);
      break;
    default:
      break;
    }
  }
}

void Client::processNotification(const QJsonObject &notification)
{
  if (notification["method"].toString() == "jobStateChanged") {
    QJsonObject params = notification["params"].toObject();
    emit jobStateChanged(
          static_cast<unsigned int>(params["moleQueueId"].toDouble()),
          params["oldState"].toString(), params["newState"].toString());
  }
}

void Client::processError(const QJsonObject &error)
{
  int localId = static_cast<int>(error["id"].toDouble());
  int errorCode = -1;
  QString errorMessage = tr("No message specified.");
  QJsonValue errorData;

  const QJsonValue &errorValue = error.value(QLatin1String("error"));
  if (errorValue.isObject()) {
    const QJsonObject errorObject = errorValue.toObject();
    if (errorObject.value("code").isDouble())
      errorCode = static_cast<int>(errorObject.value("code").toDouble());
    if (errorObject.value("message").isString())
      errorMessage = errorObject.value("message").toString();
    if (errorObject.contains("data"))
      errorData = errorObject.value("data");
  }
  emit errorReceived(localId, errorCode, errorMessage, errorData);
}

QJsonObject Client::buildRegisterOpenWithRequest(
    const QString &name, const QList<QRegExp> &filePatterns,
    const QJsonObject &handlerMethod)
{
   QJsonArray patterns;
   foreach (const QRegExp &regex, filePatterns) {
     QJsonObject pattern;
     switch (regex.patternSyntax()) {
     case QRegExp::RegExp:
     case QRegExp::RegExp2:
       pattern["regexp"] = regex.pattern();
       break;
     case QRegExp::Wildcard:
     case QRegExp::WildcardUnix:
       pattern["wildcard"] = regex.pattern();
       break;
     default:
     case QRegExp::FixedString:
     case QRegExp::W3CXmlSchema11:
       continue;
     }

     pattern["caseSensitive"] = regex.caseSensitivity() == Qt::CaseSensitive;
     patterns.append(pattern);
   }

   QJsonObject params;
   params["name"] = name;
   params["method"] = handlerMethod;
   params["patterns"] = patterns;

   QJsonObject packet = m_jsonRpcClient->emptyRequest();
   packet["method"] = QLatin1String("registerOpenWith");
   packet["params"] = params;

   return packet;
}

} // End namespace MoleQueue
} // End namespace Avogadro
