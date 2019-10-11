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

#include "configdialog.h"
#include "girderrequest.h"
#include "listmoleculesmodel.h"
#include "mongochem.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
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
  Q_UNUSED(results)

  QString message = "Upload succeeded!";
  qDebug() << message;
  QMessageBox::information(this, "MongoChem", message);
}

void MongoChemWidget::error(const QString& message, QNetworkReply* reply)
{
  Q_UNUSED(reply)
  qDebug() << "An error occurred. Message was: " << message;
  QMessageBox::critical(this, "MongoChem", message);
}

} // namespace QtPlugins
} // namespace Avogadro
