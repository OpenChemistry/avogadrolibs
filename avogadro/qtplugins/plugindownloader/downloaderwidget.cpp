/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2017 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "downloaderwidget.h"
#include "ui_downloaderwidget.h"
#include "zipextracter.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QStandardPaths>

#include <QtWidgets/QGraphicsRectItem>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTableWidgetItem>

#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>

namespace Avogadro {
namespace QtPlugins {

DownloaderWidget::DownloaderWidget(QWidget* parent)
  : QDialog(parent), m_ui(new Ui::DownloaderWidget)
{
  m_numRepos = 0;
  m_filePath =
    QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
  m_NetworkAccessManager = new QNetworkAccessManager(this);
  m_ui->setupUi(this);
  connect(m_ui->downloadButton, SIGNAL(clicked(bool)), this,
          SLOT(getCheckedRepos()));
  connect(m_ui->repoTable, SIGNAL(cellClicked(int, int)), this,
          SLOT(downloadREADME(int, int)));

  m_ui->repoTable->setColumnCount(4);
  m_ui->repoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_ui->repoTable->setHorizontalHeaderLabels(QStringList() << "Update"
                                                           << "Name"
                                                           << "Description"
                                                           << "Releases");
  m_ui->repoTable->horizontalHeader()->setStretchLastSection(true);

  m_ui->repoTable->setRowCount(0);

  getRepoData();
}

DownloaderWidget::~DownloaderWidget()
{
  delete m_ui;
  delete m_repoList;
  delete m_read;
}

// download master plugin.json from Avogadro.cc
void DownloaderWidget::getRepoData()
{
  QString url = "https://avogadro.cc/plugins.json";
  QNetworkRequest request;
  request.setRawHeader("Accept", "text/html,application/xhtml+xml,application/"
                                 "xml;q=0.9,image/webp,*/*;q=0.8");
  request.setRawHeader("User-Agent",
                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/54.0.2840.71 Safari/537.36");
  request.setRawHeader("Accept-Language", "en - US, en; q = 0.8");
  request.setUrl(url); // Set the url
  m_reply = m_NetworkAccessManager->get(request);
  connect(m_reply, SIGNAL(finished()), this, SLOT(updateRepoData()));
}

// Process the master plugin.json hosted on Avogadro.cc
void DownloaderWidget::updateRepoData()
{
  if (m_reply->error() == QNetworkReply::NoError) {
    m_read = new Json::Reader();
    // Reading the data from the response
    QByteArray bytes = m_reply->readAll();
    QString jsonString(bytes);

    // parse the json
    m_read->parse(jsonString.toStdString().c_str(), m_root);
    m_numRepos = m_root.size();
    m_repoList = new repo[m_numRepos];
    m_ui->repoTable->setRowCount(m_numRepos);
    for (int i = 0; i < m_numRepos; i++) {
      m_repoList[i].name = m_root[i].get("name", "Error").asCString();
      m_repoList[i].description =
        m_root[i].get("description", "Error").asCString();
      m_repoList[i].releaseVersion =
        m_root[i].get("release_version", "Error").asCString();
      m_repoList[i].type = m_root[i].get("type", "other").asCString();
      m_repoList[i].updatedAt =
        m_root[i].get("updated_at", "Error").asCString();
      m_repoList[i].zipballUrl =
        m_root[i].get("zipball_url", "Error").asCString();
      m_repoList[i].hasRelease = m_root[i].get("has_release", false).asBool();

      // readme should be included or at least the repo url so we don't have to
      // do this
      QStringList urlParts = m_repoList[i].zipballUrl.split("/");
      urlParts.removeLast();
      urlParts.removeLast(); // remove /zipball/(version/branch)
      urlParts.append("readme");
      QString readmeUrl = urlParts.join("/");

      m_repoList[i].readmeUrl = readmeUrl;
      QTableWidgetItem* checkbox = new QTableWidgetItem();
      checkbox->setCheckState(Qt::Unchecked);
      m_ui->repoTable->setItem(i, 0, checkbox);
      m_ui->repoTable->setItem(i, 1, new QTableWidgetItem(m_repoList[i].name));
      m_ui->repoTable->setItem(i, 2,
                               new QTableWidgetItem(m_repoList[i].description));
      if (m_repoList[i].hasRelease)
        m_ui->repoTable->setItem(
          i, 3, new QTableWidgetItem(m_repoList[i].releaseVersion));
      else
        m_ui->repoTable->setItem(i, 3,
                                 new QTableWidgetItem(m_repoList[i].updatedAt));
    }
  }
  m_reply->deleteLater();
}

// Grab README data from Github
void DownloaderWidget::downloadREADME(int row, int col)
{
  m_ui->readmeBrowser->clear();
  QString url = m_repoList[row].readmeUrl;
  QNetworkRequest request;
  request.setRawHeader("Accept", "text/html,application/xhtml+xml,application/"
                                 "xml;q=0.9,image/webp,*/*;q=0.8");
  request.setRawHeader("User-Agent",
                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/54.0.2840.71 Safari/537.36");
  request.setRawHeader("Accept-Language", "en - US, en; q = 0.8");
  request.setUrl(url); // Set the url

  m_reply = m_NetworkAccessManager->get(request);
  connect(m_reply, SIGNAL(finished()), this, SLOT(showREADME()));
}

// display README when the user clicks a row
void DownloaderWidget::showREADME()
{
  if (m_reply->error() == QNetworkReply::NoError) {
    m_read = new Json::Reader();
    // Reading the data from the response
    QByteArray bytes = m_reply->readAll();
    QString jsonString(bytes);

    // parse the json
    m_read->parse(jsonString.toStdString().c_str(), m_root);

    int resultSize = m_root.size();
    QByteArray content = m_root.get("content", "ERROR").asCString();
    m_ui->readmeBrowser->append(QByteArray::fromBase64(content).data());
  }
}

// see which repositories the user checked
void DownloaderWidget::getCheckedRepos()
{
  m_ui->readmeBrowser->clear();
  m_downloadList.clear();
  for (int i = 0; i < m_numRepos; i++) {
    if (m_ui->repoTable->item(i, 0)->checkState() == Qt::Checked) {
      downloadEntry newEntry;
      newEntry.url = m_repoList[i].zipballUrl;
      newEntry.name = m_repoList[i].name;
      newEntry.type = m_repoList[i].type;
      m_downloadList.append(newEntry);
    }
  }
  downloadNext();
}

// Used to download one zip at a time so we know which plugin data we're getting
void DownloaderWidget::downloadNext()
{
  if (!m_downloadList.isEmpty()) {
    QString url = m_downloadList.last().url;
    QNetworkRequest request;
    request.setRawHeader("Accept",
                         "text/html,application/xhtml+xml,application/"
                         "xml;q=0.9,image/webp,*/*;q=0.8");
    request.setRawHeader("User-Agent",
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/54.0.2840.71 Safari/537.36");
    request.setRawHeader("Accept-Language", "en - US, en; q = 0.8");
    request.setUrl(url); // Set the url

    m_reply = m_NetworkAccessManager->get(request);
    connect(m_reply, SIGNAL(finished()), this, SLOT(handleRedirect()));
  }
}

// The download url for Github is always a redirect to the actual zip
void DownloaderWidget::handleRedirect()
{
  if (m_reply->error() == QNetworkReply::NoError) {
    QVariant statusCode =
      m_reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    if (statusCode.toInt() == 302) {
      QVariant possibleRedirectUrl =
        m_reply->attribute(QNetworkRequest::RedirectionTargetAttribute);

      QUrl _urlRedirectedTo = possibleRedirectUrl.toUrl();

      QNetworkRequest request;
      request.setRawHeader("Accept",
                           "text/html,application/xhtml+xml,application/"
                           "xml;q=0.9,image/webp,*/*;q=0.8");
      request.setRawHeader("User-Agent",
                           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/54.0.2840.71 Safari/537.36");
      request.setRawHeader("Accept-Language", "en - US, en; q = 0.8");
      request.setUrl(_urlRedirectedTo); // Set the url
      m_reply = m_NetworkAccessManager->get(request);
      connect(m_reply, SIGNAL(finished()), this, SLOT(unzipPlugin()));
    }
  } else {
    m_reply->deleteLater();
    m_downloadList.removeLast();
    downloadNext();
  }
}

// Save and unzip the plugin zipball
void DownloaderWidget::unzipPlugin()
{
  if (m_reply->error() == QNetworkReply::NoError) {
    // done with redirect
    QByteArray fileData = m_reply->readAll();
    QDir().mkpath(m_filePath);
    QString repoName = m_downloadList.last().name;
    QString filename = repoName + ".zip";

    QString absolutePath = m_filePath + "/" + filename;
    QString extractdirectory;
    QString subdir = m_downloadList.last().type;

    extractdirectory = m_filePath + "/" + subdir + "/";

    QDir().mkpath(extractdirectory);

    m_ui->readmeBrowser->append("\nDownloading " + filename + " to " +
                                m_filePath);

    QFile out(absolutePath);
    out.open(QIODevice::WriteOnly);
    QDataStream outstr(&out);
    outstr << fileData;

    std::string extractdir = extractdirectory.toStdString();
    std::string absolutep = absolutePath.toStdString();

    ZipExtracter unzip;

    m_ui->readmeBrowser->append("Extracting " + absolutePath + " to " +
                                extractdirectory);
    QList<QString> ret = unzip.extract(extractdir, absolutep);

    if (ret.empty()) {
      m_ui->readmeBrowser->append("Extraction successful");
    } else {
      m_ui->readmeBrowser->append("Error while extracting: " + ret.first());
    }

    out.remove();
    m_reply->deleteLater();
    m_downloadList.removeLast();
    downloadNext();
  }
}

} // namespace QtPlugins
} // namespace Avogadro
