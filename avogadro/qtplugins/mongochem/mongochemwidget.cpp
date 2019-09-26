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

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTableWidgetItem>

namespace Avogadro {

namespace QtPlugins {

MongoChemWidget::MongoChemWidget(QWidget* parent)
  : QWidget(parent), m_ui(new Ui::MongoChemWidget),
    m_networkManager(new QNetworkAccessManager(this))
{
  m_ui->setupUi(this);
  setupConnections();
}

MongoChemWidget::~MongoChemWidget() = default;

void MongoChemWidget::setupConnections()
{
  connect(m_ui->pushSearch, &QPushButton::clicked, this,
          &MongoChemWidget::search);
  connect(m_ui->pushConfig, &QPushButton::clicked, this,
          &MongoChemWidget::showConfig);
}

void MongoChemWidget::authenticate()
{
  // Will get girder token from api key in the future...
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

void MongoChemWidget::finishSearch(const QVariantMap& results)
{
  // Clear the table
  m_ui->tableMolecules->clearContents();
  auto resultList = results.value("results").toList();
  int matches = resultList.size();
  if (matches == 0) {
    qDebug() << "No results found!";
    return;
  }

  m_ui->tableMolecules->setRowCount(matches);
  for (int i = 0; i < matches; ++i) {
    QString formula = resultList[i]
                        .toMap()
                        .value("properties")
                        .toMap()
                        .value("formula")
                        .toString();
    QString smiles = resultList[i].toMap().value("smiles").toString();
    QString inchikey = resultList[i].toMap().value("inchikey").toString();

    m_ui->tableMolecules->setItem(i, 0, new QTableWidgetItem(formula));
    m_ui->tableMolecules->setItem(i, 1, new QTableWidgetItem(smiles));
    m_ui->tableMolecules->setItem(i, 2, new QTableWidgetItem(inchikey));
  }
}

void MongoChemWidget::error(const QString& message, QNetworkReply* reply)
{
  Q_UNUSED(reply)
  qDebug() << "An error occurred. Message was: " << message;
}

} // namespace QtPlugins
} // namespace Avogadro
