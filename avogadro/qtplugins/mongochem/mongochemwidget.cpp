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

#include "mongochemwidget.h"
#include "ui_mongochemwidget.h"

#include "calculationsubmitter.h"
#include "calculationwatcher.h"
#include "configdialog.h"
#include "girderrequest.h"
#include "listmoleculesmodel.h"
#include "mongochem.h"
#include "submitcalculationdialog.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSettings>
#include <QTableWidgetItem>

namespace Avogadro {

namespace QtPlugins {

MongoChemWidget::MongoChemWidget(MongoChem* plugin, QWidget* parent)
  : QWidget(parent), m_plugin(plugin), m_ui(new Ui::MongoChemWidget),
    m_networkManager(new QNetworkAccessManager(this)),
    m_listMoleculesModel(new ListMoleculesModel(this))
{
  m_ui->setupUi(this);
  m_ui->tableMolecules->setModel(m_listMoleculesModel.data());
  readSettings();
  setupConnections();
}

MongoChemWidget::~MongoChemWidget() = default;

void MongoChemWidget::setupConnections()
{
  connect(m_ui->pushSearch, &QPushButton::clicked, this,
          &MongoChemWidget::search);
  connect(m_ui->pushConfig, &QPushButton::clicked, this,
          &MongoChemWidget::showConfig);
  connect(m_ui->pushDownload, &QPushButton::clicked, this,
          &MongoChemWidget::downloadSelectedMolecule);
  connect(m_ui->pushUpload, &QPushButton::clicked, this,
          &MongoChemWidget::uploadMolecule);
  connect(m_ui->pushSubmitCalculation, &QPushButton::clicked, this,
          &MongoChemWidget::submitCalculation);
}

void MongoChemWidget::readSettings()
{
  QSettings settings;
  settings.beginGroup("mongochem");
  m_girderUrl = settings.value("girderUrl", m_girderUrl).toString();
  m_apiKey = settings.value("apiKey", m_apiKey).toString();
  settings.endGroup();
}

void MongoChemWidget::writeSettings()
{
  QSettings settings;
  settings.beginGroup("mongochem");
  settings.setValue("girderUrl", m_girderUrl);
  settings.setValue("apiKey", m_apiKey);
  settings.endGroup();
}

void MongoChemWidget::authenticate()
{
  QString url = m_girderUrl + "/api_key/token";

  static const QString& tokenDuration = "90";
  QByteArray postData;
  postData.append(("key=" + m_apiKey + "&").toUtf8());
  postData.append(("duration=" + tokenDuration).toUtf8());

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->setHeader(QNetworkRequest::ContentTypeHeader,
                     "application/x-www-form-urlencoded");
  request->post(postData);

  connect(request, &GirderRequest::result, this,
          &MongoChemWidget::finishAuthentication);
  connect(request, &GirderRequest::error, this, &MongoChemWidget::error);
  connect(request, &GirderRequest::result, request,
          &GirderRequest::deleteLater);
  connect(request, &GirderRequest::error, request, &GirderRequest::deleteLater);
}

void MongoChemWidget::finishAuthentication(const QVariant& results)
{

  m_girderToken = results.toMap()["authToken"].toMap()["token"].toString();
  if (!m_girderToken.isEmpty())
    QMessageBox::information(this, "MongoChem", "Authentication Successful!");
  else
    QMessageBox::critical(this, "MongoChem", "Authentication failed!");
}

void MongoChemWidget::showConfig()
{
  if (!m_configDialog)
    m_configDialog.reset(new ConfigDialog(this));

  // Make sure the GUI variables are up-to-date
  m_configDialog->setGirderUrl(m_girderUrl);
  m_configDialog->setApiKey(m_apiKey);

  if (m_configDialog->exec()) {
    m_girderUrl = m_configDialog->girderUrl();
    m_apiKey = m_configDialog->apiKey();
    if (!m_apiKey.isEmpty())
      authenticate();

    writeSettings();
  }
}

void MongoChemWidget::search()
{
  QString url = m_girderUrl + "/molecules";

  QList<QPair<QString, QString>> urlQueries = { { "limit", "25" } };

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->setUrlQueries(urlQueries);
  request->get();

  connect(request, &GirderRequest::result, this,
          &MongoChemWidget::finishSearch);
  connect(request, &GirderRequest::error, this, &MongoChemWidget::error);
  connect(request, &GirderRequest::result, request,
          &GirderRequest::deleteLater);
  connect(request, &GirderRequest::error, request, &GirderRequest::deleteLater);
}

void MongoChemWidget::finishSearch(const QVariant& results)
{
  // Clear the table
  m_listMoleculesModel->clear();
  auto resultList = results.toMap()["results"].toList();
  int matches = resultList.size();
  if (matches == 0) {
    QString message = "No results found!";
    qDebug() << message;
    QMessageBox::critical(this, "MongoChem", message);
    return;
  }

  for (int i = 0; i < matches; ++i) {
    m_listMoleculesModel->addMolecule(resultList[i].toMap());
  }
}

int MongoChemWidget::selectedRow()
{
  auto rows = m_ui->tableMolecules->selectionModel()->selectedRows();
  if (rows.isEmpty()) {
    qDebug() << "No row selected!";
    return -1;
  }

  return rows[0].row();
}

void MongoChemWidget::downloadSelectedMolecule()
{
  int row = selectedRow();
  if (row < 0) {
    QString message = "No molecule selected!";
    qDebug() << message;
    QMessageBox::critical(this, "MongoChem", message);
    return;
  }

  auto moleculeId = m_listMoleculesModel->moleculeId(row);
  auto moleculeName = m_listMoleculesModel->moleculeName(row);

  // It would be better if we set the name after downloading the
  // molecule succeeded, but that is currently not easy...
  m_plugin->setMoleculeName(moleculeName);

  QString url = (m_girderUrl + "/molecules/%1/cjson").arg(moleculeId);

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->get();

  connect(request, &GirderRequest::result, this,
          &MongoChemWidget::finishDownloadMolecule);
  connect(request, &GirderRequest::error, this, &MongoChemWidget::error);
  connect(request, &GirderRequest::result, request,
          &GirderRequest::deleteLater);
  connect(request, &GirderRequest::error, request, &GirderRequest::deleteLater);
}

void MongoChemWidget::finishDownloadMolecule(const QVariant& results)
{
  auto cjsonDoc = QJsonDocument::fromVariant(results);
  if (cjsonDoc.isEmpty()) {
    qDebug() << "No cjson found in the results!";
    return;
  }

  m_plugin->setMoleculeData(cjsonDoc.toJson());
}

void MongoChemWidget::uploadMolecule()
{
  if (m_girderToken.isEmpty()) {
    QString message = "Login required to upload";
    qDebug() << message;
    QMessageBox::critical(this, "MongoChem", message);
    return;
  }

  QString cjson = m_plugin->currentMoleculeCjson();

  // If there is no molecule, the cjson will look like this:
  // {\n  \"chemicalJson\": 1\n}
  if (!cjson.contains("atoms")) {
    QString message = "No molecule found!";
    qDebug() << message;
    QMessageBox::critical(this, "MongoChem", message);
    return;
  }
  QJsonObject object({ { "cjson", cjson } });
  QByteArray postData = QJsonDocument(object).toJson();

  QString url = m_girderUrl + "/molecules";

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  request->post(postData);

  connect(request, &GirderRequest::result, this,
          &MongoChemWidget::finishUploadMolecule);
  connect(request, &GirderRequest::error, this, &MongoChemWidget::error);
  connect(request, &GirderRequest::result, request,
          &GirderRequest::deleteLater);
  connect(request, &GirderRequest::error, request, &GirderRequest::deleteLater);
}

void MongoChemWidget::finishUploadMolecule(const QVariant& results)
{
  auto moleculeId = results.toMap()["_id"].toString();
  if (moleculeId.isEmpty()) {
    QString message = "Failed to upload molecule";
    qDebug() << message;
    QMessageBox::critical(this, "MongoChem", message);
    return;
  }

  // Now, upload the particular geometry
  uploadGeometry(moleculeId);
}

void MongoChemWidget::uploadGeometry(const QString& moleculeId)
{
  QByteArray postData = m_plugin->currentMoleculeCjson().toLatin1();

  QString url =(m_girderUrl + "/molecules/%1/geometries").arg(moleculeId);

  QList<QPair<QString, QString>> urlQueries = {
    { "provenanceType", "Uploaded by Avogadro2 User" }
  };

  auto* request =
    new GirderRequest(m_networkManager.data(), url, m_girderToken);
  request->setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
  request->setUrlQueries(urlQueries);
  request->post(postData);

  connect(request, &GirderRequest::result, this,
          &MongoChemWidget::finishUploadGeometry);
  connect(request, &GirderRequest::error, this, &MongoChemWidget::error);
  connect(request, &GirderRequest::result, request,
          &GirderRequest::deleteLater);
  connect(request, &GirderRequest::error, request, &GirderRequest::deleteLater);
}

void MongoChemWidget::finishUploadGeometry(const QVariant& results)
{
  auto geometryId = results.toMap()["_id"].toString();
  if (geometryId.isEmpty()) {
    QString message = "Failed to upload geometry";
    qDebug() << message;
    QMessageBox::critical(this, "MongoChem", message);
    return;
  }

  QString message = "Upload successful!";
  qDebug() << message;
  QMessageBox::information(this, "MongoChem", message);
}

void MongoChemWidget::submitCalculation()
{
  if (m_girderToken.isEmpty()) {
    QString message = "Login required to submit calculation";
    qDebug() << message;
    QMessageBox::critical(this, "MongoChem", message);
    return;
  }

  QString cjson = m_plugin->currentMoleculeCjson();

  // If there is no molecule, the cjson will look like this:
  // {\n  \"chemicalJson\": 1\n}
  if (!cjson.contains("atoms")) {
    QString message = "No molecule found!";
    qDebug() << message;
    QMessageBox::critical(this, "MongoChem", message);
    return;
  }

  if (!m_submitCalculationDialog)
    m_submitCalculationDialog.reset(new SubmitCalculationDialog);

  if (!m_submitCalculationDialog->exec())
    return;

  QString container = m_submitCalculationDialog->containerName();
  QString image = m_submitCalculationDialog->imageName();
  QVariantMap inputParameters = m_submitCalculationDialog->inputParameters();

  auto calcSubmitter = new CalculationSubmitter(m_networkManager, m_girderUrl,
                                                m_girderToken, this);

  calcSubmitter->setMoleculeCjson(cjson);
  calcSubmitter->setContainerName(container);
  calcSubmitter->setImageName(image);
  calcSubmitter->setInputParameters(inputParameters);
  calcSubmitter->start();

  connect(calcSubmitter, &CalculationSubmitter::finished, this,
          &MongoChemWidget::finishSubmitCalculation);
  connect(calcSubmitter, &CalculationSubmitter::error, this,
          &MongoChemWidget::error);
  connect(calcSubmitter, &CalculationSubmitter::finished, calcSubmitter,
          &CalculationSubmitter::deleteLater);
  connect(calcSubmitter, &CalculationSubmitter::error, calcSubmitter,
          &CalculationSubmitter::deleteLater);
}

void MongoChemWidget::finishSubmitCalculation(const QVariantMap& results)
{
  QString message = "Calculation submitted!";
  qDebug() << message;
  QMessageBox::information(this, "MongoChem", message);

  QString pendingCalculationId = results["pendingCalculationId"].toString();

  auto watcher = new CalculationWatcher(
    m_networkManager, m_girderUrl, m_girderToken, pendingCalculationId, this);

  watcher->start();

  connect(watcher, &CalculationWatcher::finished, this,
          &MongoChemWidget::finishWatchCalculation);
  connect(watcher, &CalculationWatcher::error, this, &MongoChemWidget::error);
  connect(watcher, &CalculationWatcher::finished, watcher,
          &CalculationWatcher::deleteLater);
  connect(watcher, &CalculationWatcher::error, watcher,
          &CalculationWatcher::deleteLater);
}

void MongoChemWidget::finishWatchCalculation(const QByteArray& cjson)
{
  QString msg = "Calculation complete. Download the results?";
  if (QMessageBox::question(this, "MongoChem", msg)) {
    m_plugin->setMoleculeName("calculation");
    m_plugin->setMoleculeData(cjson);
  }
}

void MongoChemWidget::error(const QString& message, QNetworkReply* reply)
{
  Q_UNUSED(reply)
  qDebug() << "An error occurred. Message was: " << message;
  QMessageBox::critical(this, "MongoChem", message);
}

} // namespace QtPlugins
} // namespace Avogadro
