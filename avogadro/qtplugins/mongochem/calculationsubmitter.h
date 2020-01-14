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

#ifndef AVOGADRO_QTPLUGINS_CALCULATIONSUBMITTER_H
#define AVOGADRO_QTPLUGINS_CALCULATIONSUBMITTER_H

#include <QSharedPointer>
#include <QVariant>
#include <QVariantMap>

class QNetworkAccessManager;
class QNetworkReply;

namespace Avogadro {
namespace QtPlugins {

class CalculationSubmitter : public QObject
{
  Q_OBJECT

public:
  explicit CalculationSubmitter(QSharedPointer<QNetworkAccessManager> manager,
                                const QString& girderUrl,
                                const QString& girderToken,
                                QObject* parent = nullptr);
  ~CalculationSubmitter() override;

  void setMoleculeCjson(const QString& cjson) { m_moleculeCjson = cjson; }
  void setContainerName(const QString& name) { m_containerName = name; }
  void setImageName(const QString& name) { m_imageName = name; }
  void setInputParameters(const QVariantMap& m) { m_inputParameters = m; }

  void start();

signals:
  // The results will contain "calculationId" if the calculation has
  // already been done before. The results will contain "taskFlowId"
  // if a new calculation was submitted.
  void finished(const QVariantMap& results);
  void error(const QString& errorMessage, QNetworkReply* error = nullptr);

private slots:
  void uploadMolecule();
  void finishUploadMolecule(const QVariant& results);

  void uploadGeometry();
  void finishUploadGeometry(const QVariant& results);

  void fetchCalculation();
  void finishFetchCalculation(const QVariant& results);

  void fetchCluster();
  void finishFetchCluster(const QVariant& results);

  void fetchOrCreateQueue();
  void finishFetchOrCreateQueue(const QVariant& results);

  void createQueue();
  void finishCreateQueue(const QVariant& results);

  void createPendingCalculation();
  void finishCreatePendingCalculation(const QVariant& results);

  void createTaskFlow();
  void finishCreateTaskFlow(const QVariant& results);

  void addTaskFlowToQueue();
  void finishAddTaskFlowToQueue(const QVariant& results);

  void popQueue();
  void finishPopQueue(const QVariant& results);

  void handleError(const QString& msg, QNetworkReply* networkReply);

private:
  QString m_girderUrl = "http://localhost:8080/api/v1";
  QString m_girderToken;

  // These should be set before starting
  QString m_moleculeCjson;
  QString m_containerName;
  QString m_imageName;
  QVariantMap m_inputParameters;

  // These will be set during the process
  QString m_moleculeId;
  QString m_geometryId;
  QString m_pendingCalculationId;
  QString m_clusterId;
  QString m_queueId;
  QString m_taskFlowId;

  QSharedPointer<QNetworkAccessManager> m_networkManager;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CALCULATIONSUBMITTER_H
