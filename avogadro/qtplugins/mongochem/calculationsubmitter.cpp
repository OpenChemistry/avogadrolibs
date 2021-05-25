/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2019 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "calculationsubmitter.h"

#include "girderrequest.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QNetworkAccessManager>
#include <QNetworkReply>

namespace Avogadro {
namespace QtPlugins {

static void deleteRequestWhenFinished(GirderRequest* r)
{
  QObject::connect(r, &GirderRequest::result, r, &GirderRequest::deleteLater);
  QObject::connect(r, &GirderRequest::error, r, &GirderRequest::deleteLater);
}

CalculationSubmitter::CalculationSubmitter(
  QSharedPointer<QNetworkAccessManager> manager, const QString& girderUrl,
  const QString& girderToken, QObject* parent)
  : QObject(parent), m_girderUrl(girderUrl), m_girderToken(girderToken),
    m_networkManager(manager)
{}

CalculationSubmitter::~CalculationSubmitter() = default;

static bool parseImageName(const QString& imageName, QString& repository,
                           QString& tag)
{
  auto split = imageName.split(":");
  repository = split[0];

  if (split.size() > 1)
    tag = split[1];
  else
    tag = "latest";

  return true;
}

void CalculationSubmitter::start()
{
  // Start by uploading the molecule (but note that if a molecule
  // with a matching inchikey exists, that one will be used instead)
  uploadMolecule();
}

void CalculationSubmitter::uploadMolecule()
{
  QJsonObject object({ { "cjson", m_moleculeCjson } });
  QByteArray postData = QJsonDocument(object).toJson();

  QString url = m_girderUrl + "/molecules";

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  request->post(postData);

  connect(request, &GirderRequest::result, this,
          &CalculationSubmitter::finishUploadMolecule);
  connect(request, &GirderRequest::error, this, &CalculationSubmitter::error);
  deleteRequestWhenFinished(request);
}

void CalculationSubmitter::finishUploadMolecule(const QVariant& results)
{
  m_moleculeId = results.toMap()["_id"].toString();
  if (m_moleculeId.isEmpty()) {
    emit error("Failed to upload molecule!");
    return;
  }

  // Now, upload the particular geometry that we will use
  uploadGeometry();
}

void CalculationSubmitter::uploadGeometry()
{
  QByteArray postData = m_moleculeCjson.toLatin1();

  QString url =(m_girderUrl + "/molecules/%1/geometries").arg(m_moleculeId);

  QList<QPair<QString, QString>> urlQueries = {
    { "provenanceType", "Uploaded from Avogadro2" }
  };

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  request->setUrlQueries(urlQueries);
  request->post(postData);

  connect(request, &GirderRequest::result, this,
          &CalculationSubmitter::finishUploadGeometry);
  connect(request, &GirderRequest::error, this, &CalculationSubmitter::error);
  deleteRequestWhenFinished(request);
}

void CalculationSubmitter::finishUploadGeometry(const QVariant& results)
{
  m_geometryId = results.toMap()["_id"].toString();
  if (m_geometryId.isEmpty()) {
    emit error("Failed to upload geometry!");
    return;
  }

  // Now, make sure the calculation has not already been done before.
  fetchCalculation();
}

void CalculationSubmitter::fetchCalculation()
{
  QString repository, tag;
  parseImageName(m_imageName, repository, tag);
  QByteArray inputParams = QJsonDocument::fromVariant(m_inputParameters)
                             .toJson(QJsonDocument::Compact);

  QString url = m_girderUrl + "/calculations";

  QList<QPair<QString, QString>> urlQueries = {
    { "moleculeId", m_moleculeId },
    { "geometryId", m_geometryId },
    { "inputParameters", inputParams },
    { "imageName", QString("%1:%2").arg(repository).arg(tag) }
  };

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->setUrlQueries(urlQueries);
  request->get();

  connect(request, &GirderRequest::result, this,
          &CalculationSubmitter::finishFetchCalculation);
  connect(request, &GirderRequest::error, this,
          &CalculationSubmitter::handleError);
  deleteRequestWhenFinished(request);
}

void CalculationSubmitter::finishFetchCalculation(const QVariant& results)
{
  auto resultsList = results.toMap()["results"].toList();
  if (resultsList.size() != 0) {
    // The calculation has already been done. Get the id and emit it.
    QVariantMap output;
    output["calculationId"] = resultsList[0].toMap()["_id"].toString();
    // TODO: We are currently always submitting the calculation
    // It might be nice in the future to fetch it if it has already
    // been done.
    /*
    emit finished(output);
    return;
    */
  }

  fetchCluster();
}

void CalculationSubmitter::fetchCluster()
{
  // Just grab the first cluster we can find...
  QString url = m_girderUrl + "/clusters";

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->get();

  connect(request, &GirderRequest::result, this,
          &CalculationSubmitter::finishFetchCluster);
  connect(request, &GirderRequest::error, this,
          &CalculationSubmitter::handleError);
  deleteRequestWhenFinished(request);
}

void CalculationSubmitter::finishFetchCluster(const QVariant& results)
{
  auto resultsList = results.toList();
  if (resultsList.size() == 0) {
    emit error("No clusters found!");
    return;
  }

  m_clusterId = resultsList[0].toMap()["_id"].toString();
  if (m_clusterId.isEmpty()) {
    emit error("Cluster ID not found!");
    return;
  }

  fetchOrCreateQueue();
}

void CalculationSubmitter::fetchOrCreateQueue()
{
  // First try a fetch...
  QString url = m_girderUrl + "/queues";
  QList<QPair<QString, QString>> urlQueries = { { "name", "oc_queue" } };

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->setUrlQueries(urlQueries);
  request->get();

  connect(request, &GirderRequest::result, this,
          &CalculationSubmitter::finishFetchOrCreateQueue);
  connect(request, &GirderRequest::error, this,
          &CalculationSubmitter::handleError);
  deleteRequestWhenFinished(request);
}

void CalculationSubmitter::finishFetchOrCreateQueue(const QVariant& results)
{
  auto resultsList = results.toList();
  if (resultsList.size() == 0) {
    // Create the queue
    createQueue();
    return;
  }

  m_queueId = resultsList[0].toMap()["_id"].toString();
  if (m_queueId.isEmpty()) {
    emit error("Queue ID not found!");
    return;
  }

  createPendingCalculation();
}

void CalculationSubmitter::createQueue()
{
  QString url = m_girderUrl + "/queues";
  QList<QPair<QString, QString>> urlQueries = { { "name", "oc_queue" },
                                                { "maxRunning", "5" } };

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->setUrlQueries(urlQueries);
  request->setHeader(QNetworkRequest::ContentTypeHeader,
                     "application/x-www-form-urlencoded");

  // The post data is empty in this case
  request->post("");

  connect(request, &GirderRequest::result, this,
          &CalculationSubmitter::finishCreateQueue);
  connect(request, &GirderRequest::error, this,
          &CalculationSubmitter::handleError);
  deleteRequestWhenFinished(request);
}

void CalculationSubmitter::finishCreateQueue(const QVariant& results)
{
  m_queueId = results.toMap()["_id"].toString();
  if (m_queueId.isEmpty()) {
    emit error("Failed to create queue!");
    return;
  }

  createPendingCalculation();
}

void CalculationSubmitter::createPendingCalculation()
{
  QString repository, tag;
  parseImageName(m_imageName, repository, tag);

  /**
   * Needs to look something like this:
   *  {
   *    'moleculeId': molecule_id,
   *    'cjson': None,
   *    'public': True,
   *    'properties': {
   *        'pending': True
   *    },
   *    'input': {
   *        'parameters': input_parameters,
   *    },
   *    'image': {
   *        'repository': repository,
   *        'tag': tag
   *    }
   *  }
   *
   *
   * TODO: Maybe we can find a more concise way to do this in
   * the future?
   */

  QJsonObject json;
  json["moleculeId"] = m_moleculeId;
  json["geometryId"] = m_geometryId;
  json["public"] = true;
  json["cjson"] = QJsonValue();

  QJsonObject properties;
  properties["pending"] = true;
  json["properties"] = properties;

  QJsonObject input;
  input["parameters"] = QJsonValue::fromVariant(m_inputParameters);
  json["input"] = input;

  QJsonObject image;
  image["repository"] = repository;
  image["tag"] = tag;
  json["image"] = image;

  QString url = m_girderUrl + "/calculations";
  QByteArray postData = QJsonDocument(json).toJson(QJsonDocument::Compact);

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  request->post(postData);

  connect(request, &GirderRequest::result, this,
          &CalculationSubmitter::finishCreatePendingCalculation);
  connect(request, &GirderRequest::error, this, &CalculationSubmitter::error);
  deleteRequestWhenFinished(request);
}

void CalculationSubmitter::finishCreatePendingCalculation(
  const QVariant& results)
{
  m_pendingCalculationId = results.toMap()["_id"].toString();
  if (m_pendingCalculationId.isEmpty()) {
    emit error("Failed to create pending calculation");
    return;
  }

  createTaskFlow();
}

void CalculationSubmitter::createTaskFlow()
{
  QString repository, tag;
  parseImageName(m_imageName, repository, tag);

  QJsonObject json;
  json["taskFlowClass"] = "taskflows.OpenChemistryTaskFlow";

  QJsonObject meta;
  meta["calculationIds"] = QJsonArray({ m_pendingCalculationId });

  QJsonObject image;
  image["repository"] = repository;
  image["tag"] = tag;
  meta["image"] = image;

  json["meta"] = meta;

  QString url = m_girderUrl + "/taskflows";
  QByteArray postData = QJsonDocument(json).toJson(QJsonDocument::Compact);

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  request->post(postData);

  connect(request, &GirderRequest::result, this,
          &CalculationSubmitter::finishCreateTaskFlow);
  connect(request, &GirderRequest::error, this, &CalculationSubmitter::error);
  deleteRequestWhenFinished(request);
}

void CalculationSubmitter::finishCreateTaskFlow(const QVariant& results)
{
  m_taskFlowId = results.toMap()["_id"].toString();
  if (m_taskFlowId.isEmpty()) {
    emit error("Failed to create taskflow!");
    return;
  }

  addTaskFlowToQueue();
}

void CalculationSubmitter::addTaskFlowToQueue()
{
  QString repository, tag;
  parseImageName(m_imageName, repository, tag);

  QJsonObject json;
  json["runParameters"] = QJsonObject();

  QJsonObject input;
  input["calculations"] = QJsonArray({ m_pendingCalculationId });
  json["input"] = input;

  QJsonObject image;
  image["repository"] = repository;
  image["tag"] = tag;
  json["image"] = image;

  QJsonObject cluster;
  cluster["_id"] = m_clusterId;
  json["cluster"] = cluster;

  QString url =
    (m_girderUrl + "/queues/%1/add/%2").arg(m_queueId).arg(m_taskFlowId);
  QByteArray data = QJsonDocument(json).toJson(QJsonDocument::Compact);

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  request->put(data);

  connect(request, &GirderRequest::result, this,
          &CalculationSubmitter::finishAddTaskFlowToQueue);
  connect(request, &GirderRequest::error, this, &CalculationSubmitter::error);
  deleteRequestWhenFinished(request);
}

void CalculationSubmitter::finishAddTaskFlowToQueue(const QVariant& results)
{
  popQueue();
}

void CalculationSubmitter::popQueue()
{
  QString url = (m_girderUrl + "/queues/%1/pop").arg(m_queueId);

  QList<QPair<QString, QString>> urlQueries = { { "multi", "true" } };

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->setUrlQueries(urlQueries);
  request->setHeader(QNetworkRequest::ContentTypeHeader,
                     "application/x-www-form-urlencoded");
  request->put("");

  connect(request, &GirderRequest::result, this,
          &CalculationSubmitter::finishPopQueue);
  connect(request, &GirderRequest::error, this, &CalculationSubmitter::error);
  deleteRequestWhenFinished(request);
}

void CalculationSubmitter::finishPopQueue(const QVariant& results)
{
  QVariantMap output;
  output["pendingCalculationId"] = m_pendingCalculationId;
  output["taskFlowId"] = m_taskFlowId;
  emit finished(output);
}

void CalculationSubmitter::handleError(const QString& msg,
                                       QNetworkReply* networkReply)
{
  QString message = msg;
  if (!msg.startsWith("Girder error:"))
    message.prepend("Girder error:");

  emit error(message, networkReply);
}

} // namespace QtPlugins
} // namespace Avogadro
