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

class MongoChemWidget::Impl : public QObject
{
  Q_OBJECT

public:
  Ui::MongoChemWidget m_ui;
  QScopedPointer<QNetworkAccessManager> m_networkManager;
  std::unique_ptr<GirderRequest> m_request;

  Impl(QObject* parent = nullptr)
    : QObject(parent), m_networkManager(new QNetworkAccessManager(this))
  {
    // We know that the parent is MongoChemWidget...
    m_ui.setupUi(qobject_cast<MongoChemWidget*>(parent));
    setupConnections();
  }

  void setupConnections()
  {
    connect(m_ui.push_search, &QPushButton::clicked, this, &Impl::search);
  }

  void search()
  {
    QString url = "http://localhost:8080/api/v1";
    QString token = "";
    m_request.reset(
      new GetMoleculesRequest(m_networkManager.data(), url, token));
    m_request->send();
    connect(m_request.get(), &GetMoleculesRequest::result, this,
            &Impl::finishSearch);
    connect(m_request.get(), &GetMoleculesRequest::error, this, &Impl::error);
  }

public slots:

  void finishSearch(const QVariantMap& results)
  {

    // Clear the table
    m_ui.table_molecules->clearContents();
    auto resultList = results.value("results").toList();
    int matches = resultList.size();
    if (matches == 0) {
      qDebug() << "No results found!";
      return;
    }

    m_ui.table_molecules->setRowCount(matches);
    for (int i = 0; i < matches; ++i) {
      QString formula = resultList[i]
                          .toMap()
                          .value("properties")
                          .toMap()
                          .value("formula")
                          .toString();
      QString smiles = resultList[i].toMap().value("smiles").toString();
      QString inchikey = resultList[i].toMap().value("inchikey").toString();

      m_ui.table_molecules->setItem(i, 0, new QTableWidgetItem(formula));
      m_ui.table_molecules->setItem(i, 1, new QTableWidgetItem(smiles));
      m_ui.table_molecules->setItem(i, 2, new QTableWidgetItem(inchikey));
    }
  }

  void error(const QString& message, QNetworkReply* reply)
  {
    Q_UNUSED(reply)
    qDebug() << "An error occurred. Message was: " << message;
  }
};

MongoChemWidget::MongoChemWidget(QWidget* parent)
  : QWidget(parent), m_impl(new Impl(this))
{}

MongoChemWidget::~MongoChemWidget() = default;

} // namespace QtPlugins
} // namespace Avogadro

#include "mongochemwidget.moc"
