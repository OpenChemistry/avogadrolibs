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
}

void MongoChemWidget::search()
{
  QString url = "http://localhost:8080/api/v1";
  QString token = "";
  auto* request = new GetMoleculesRequest(m_networkManager.data(), url, token);
  request->send();
  connect(request, &GetMoleculesRequest::result, this,
          &MongoChemWidget::finishSearch);
  connect(request, &GetMoleculesRequest::error, this, &MongoChemWidget::error);
  connect(request, &GetMoleculesRequest::result, request,
          &GetMoleculesRequest::deleteLater);
  connect(request, &GetMoleculesRequest::error, request,
          &GetMoleculesRequest::deleteLater);
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
