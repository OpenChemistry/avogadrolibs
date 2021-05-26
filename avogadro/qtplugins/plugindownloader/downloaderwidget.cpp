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
#include <QtCore/QRegularExpression>
#include <QtCore/QStandardPaths>

#include <QtWidgets/QGraphicsRectItem>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTableWidgetItem>

#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>

using json = nlohmann::json;

namespace Avogadro {
namespace QtPlugins {

void setRawHeaders(QNetworkRequest* request)
{
  request->setRawHeader("Accept", "text/html,application/xhtml+xml,application/"
                                  "xml;q=0.9,image/webp,*/*;q=0.8");
  request->setRawHeader("User-Agent",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/54.0.2840.71 Safari/537.36");
  request->setRawHeader("Accept-Language", "en - US, en; q = 0.8");

  return;
}

DownloaderWidget::DownloaderWidget(QWidget* parent)
  : QDialog(parent), m_ui(new Ui::DownloaderWidget)
{
  m_filePath =
    QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
  m_NetworkAccessManager = new QNetworkAccessManager(this);
  m_ui->setupUi(this);
  // enable links in the readme to open an external browser
  m_ui->readmeBrowser->setOpenExternalLinks(true);

  connect(m_ui->downloadButton, SIGNAL(clicked(bool)), this,
          SLOT(getCheckedRepos()));
  connect(m_ui->repoTable, SIGNAL(cellClicked(int, int)), this,
          SLOT(downloadREADME(int, int)));

  m_ui->repoTable->setColumnCount(4);
  m_ui->repoTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_ui->repoTable->setHorizontalHeaderLabels(
    QStringList() << tr("Update") << tr("Name") << tr("Version")
                  << tr("Description"));
  m_ui->repoTable->horizontalHeader()->setSectionResizeMode(
    QHeaderView::ResizeToContents);
  m_ui->repoTable->horizontalHeader()->setStretchLastSection(true);

  m_ui->repoTable->setRowCount(0);
  m_ui->repoTable->verticalHeader()->hide();

  getRepoData();
}

DownloaderWidget::~DownloaderWidget()
{
  delete m_ui;
}

// download master plugin.json from Avogadro.cc
void DownloaderWidget::getRepoData(QString url)
{
  QNetworkRequest request;
  setRawHeaders(&request);
  request.setUrl(url); // Set the url
  m_reply = m_NetworkAccessManager->get(request);
  connect(m_reply, SIGNAL(finished()), this, SLOT(updateRepoData()));
}

// Process the master plugin.json hosted on Avogadro.cc
void DownloaderWidget::updateRepoData()
{
  if (m_reply->error() == QNetworkReply::NoError) {
    // Reading the data from the response
    QByteArray bytes = m_reply->readAll();

    // parse the json
    m_root = json::parse(bytes.data());
    int numRepos = m_root.size();
    m_ui->repoTable->setRowCount(numRepos);
    m_repoList.clear();
    for (int i = 0; i < numRepos; i++) {
      m_repoList.push_back(repo());

      const auto& currentRoot = m_root[i];

      // Loop through the keys
      for (auto it = currentRoot.cbegin(); it != currentRoot.cend(); ++it) {
        if (it.key() == "name" && it.value().is_string())
          m_repoList[i].name = it.value().get<std::string>().c_str();
        else if (it.key() == "description" && it.value().is_string())
          m_repoList[i].description = it.value().get<std::string>().c_str();
        else if (it.key() == "release_version" && it.value().is_string())
          m_repoList[i].releaseVersion = it.value().get<std::string>().c_str();
        else if (it.key() == "type" && it.value().is_string())
          m_repoList[i].type = it.value().get<std::string>().c_str();
        else if (it.key() == "updated_at" && it.value().is_string()) {
          // format the date, e.g. 2021-05-21T15:25:32Z
          QString format("yyyy-MM-ddTHH:mm:ssZ");
          QDateTime dateTime = QDateTime::fromString(
            it.value().get<std::string>().c_str(), format);
          m_repoList[i].updatedAt =
            QLocale().toString(dateTime.date(), QLocale::ShortFormat);
        } else if (it.key() == "zipball_url" && it.value().is_string())
          m_repoList[i].zipballUrl = it.value().get<std::string>().c_str();
        else if (it.key() == "has_release" && it.value().is_boolean())
          m_repoList[i].hasRelease = it.value().get<bool>();
        else if (it.key() == "repo_url" && it.value().is_string())
          m_repoList[i].baseUrl = it.value().get<std::string>().c_str();
        else if (it.key() == "readme_url" && it.value().is_string())
          m_repoList[i].readmeUrl = it.value().get<std::string>().c_str();
      }

      QStringList urlParts;
      QString readmeUrl;
      // If the readme wasn't supplied with the JSON, figure it out
      if (m_repoList[i].readmeUrl == "Error") {
        if (m_repoList[i].baseUrl != "Error")
          urlParts = m_repoList[i].baseUrl.split("/");
        else {
          urlParts = m_repoList[i].zipballUrl.split("/");
          urlParts.removeLast();
          urlParts.removeLast(); // remove /zipball/(version/branch)
          // save this as the base URL
          m_repoList[i].baseUrl = urlParts.join("/");
        }
        urlParts.append("readme");
        readmeUrl = urlParts.join("/");
        m_repoList[i].readmeUrl = readmeUrl;
      }

      QTableWidgetItem* checkbox = new QTableWidgetItem();
      checkbox->setCheckState(Qt::Unchecked);
      m_ui->repoTable->setItem(i, 0, checkbox);
      m_ui->repoTable->setItem(i, 1, new QTableWidgetItem(m_repoList[i].name));
      if (m_repoList[i].hasRelease)
        m_ui->repoTable->setItem(
          i, 2, new QTableWidgetItem(m_repoList[i].releaseVersion));
      else
        m_ui->repoTable->setItem(i, 2,
                                 new QTableWidgetItem(m_repoList[i].updatedAt));
      m_ui->repoTable->setItem(i, 3,
                               new QTableWidgetItem(m_repoList[i].description));
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
  setRawHeaders(&request);
  request.setUrl(url); // Set the url

  m_reply = m_NetworkAccessManager->get(request);
  connect(m_reply, SIGNAL(finished()), this, SLOT(showREADME()));
}

// display README when the user clicks a row
void DownloaderWidget::showREADME()
{
  if (m_reply->error() == QNetworkReply::NoError) {
    // Reading the data from the response
    QByteArray bytes = m_reply->readAll();

    // parse the json
    m_root = json::parse(bytes.data());

    QByteArray content("ERROR");
    if (m_root.find("content") != m_root.end() &&
        m_root["content"].is_string()) {
      content = m_root["content"].get<std::string>().c_str();
    }

#if QT_VERSION >= 0x050E00
    m_ui->readmeBrowser->setMarkdown(QByteArray::fromBase64(content).data());
#else
    // adapt some of the text to HTML using regex
    QString readme(QByteArray::fromBase64(content).data());

    // This isn't ideal, but works for a bunch of common markdown
    // adapted from Slimdown - MIT license
    // https://gist.github.com/jbroadway/2836900

    // h3 through h1
    readme.replace(QRegularExpression("### (.*)"), "<h3>\\1</h3>");
    readme.replace(QRegularExpression("## (.*)"), "<h2>\\1</h2>");
    readme.replace(QRegularExpression("# (.*)"), "<h1>\\1</h1>");
    // headers using text && -----
    readme.replace(QRegularExpression("\\n([a-zA-Z].*)\\n-{5,}\\n"),
                   "<h2>\\1</h2>");
    // headers using text && =====
    readme.replace(QRegularExpression("\\n([a-zA-Z].*)\\n={5,}\\n"),
                   "<h1>\\1</h1>");
    // links
    readme.replace(QRegularExpression("\\[([^\\[]+)\\]\\(([^\\)]+)\\)"),
                   "<a href=\'\\2\'>\\1</a>");
    // bold
    readme.replace(QRegularExpression("(\\*\\*|__)(.*?)\\1"),
                   "<strong>\\2</strong>");
    // italic
    readme.replace(QRegularExpression("(\\*|_)(.*?)\\1"), "<em>\\2</em>");
    // code
    readme.replace(QRegularExpression("`(.*?)`"), "<code>\\1</code>");
    // horizontal lines
    readme.replace(QRegularExpression("\\n-{5,}"), "\n<hr />");
    // bullets (e.g., * or -)
    readme.replace(QRegularExpression("\\n\\*(.*)"),
                   "\n<ul>\n\t<li>\\1</li>\n</ul>");
    readme.replace(QRegularExpression("\\n-(.*)"),
                   "\n<ul>\n\t<li>\\1</li>\n</ul>");
    // fixup multiple </ul><ul> bits
    readme.replace(QRegularExpression("<\\/ul>\\s?<ul>"), "");
    // paragraphs .. doesn't seem needed
    // readme.replace(QRegularExpression("\\n([^\\n]+)\\n"), "<p>\\1</p>");
    m_ui->readmeBrowser->setHtml(readme);
#endif
  }
}

// see which repositories the user checked
void DownloaderWidget::getCheckedRepos()
{
  m_ui->readmeBrowser->clear();
  m_downloadList.clear();
  for (size_t i = 0; i < m_repoList.size(); i++) {
    QTableWidgetItem* row = m_ui->repoTable->item(i, 0);
    if (row == nullptr)
      continue;

    if (row->checkState() == Qt::Checked || row->isSelected()) {
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
    setRawHeaders(&request);
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
      setRawHeaders(&request);
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
    QDir().mkpath(m_filePath); // create any needed directories for the download
    QString repoName = m_downloadList.last().name;
    QString filename = repoName + ".zip";

    QString absolutePath = m_filePath + "/" + filename;
    QString extractDirectory;
    QString subdir = m_downloadList.last().type;

    extractDirectory = m_filePath + "/" + subdir + "/";

    // create the destination directory if it doesn't exist
    QDir().mkpath(extractDirectory);

    m_ui->readmeBrowser->append(
      tr("Downloading %1 to %2\n").arg(filename).arg(m_filePath));

    QFile out(absolutePath);
    out.open(QIODevice::WriteOnly);
    out.write(fileData);
    out.close();

    std::string extractdir = extractDirectory.toStdString();
    std::string absolutep = absolutePath.toStdString();

    ZipExtracter unzip;

    m_ui->readmeBrowser->append(
      tr("Extracting %1 to %2\n").arg(absolutePath).arg(extractDirectory));
    QList<QString> newFiles = unzip.listFiles(absolutep);
    m_ui->readmeBrowser->append(
      tr("Finished %1 files\n").arg(newFiles.length()));

    QList<QString> ret = unzip.extract(extractdir, absolutep);
    if (ret.empty()) {
      m_ui->readmeBrowser->append(tr("Extraction successful\n"));

      // get the list of files / directories we unzipped
      // the first one is the main directory name
      if (newFiles.length() > 0) // got an empty archive
      {
        // check for a previous version of this plugin and remove it
        // e.g. we extracted to a path like User-Repo-GitHash
        //     OpenChemistry-crystals-a7c672d
        // we want to check for OpenChemistry-crystals
        QStringList namePieces = newFiles[0].split('-');
        if (namePieces.length() >= 3) {
          namePieces.removeLast();  // drop the hash
          namePieces.removeFirst(); // drop the org

          QString component = namePieces.join('-');

          // Check if there's a previous install
          QString destination(extractDirectory + '/' + component);
          QDir previousInstall(destination);
          if (previousInstall.exists())
            previousInstall.removeRecursively();

          // and move the directory into place, e.g.
          // OpenChemistry-crystals-a7c672d
          QDir().rename(extractDirectory + '/' + newFiles[0], destination);
        }
      }
    } else {
      m_ui->readmeBrowser->append(
        tr("Error while extracting: %1").arg(ret.first()));
    }

    out.remove(); // remove the ZIP file
    m_reply->deleteLater();
    m_downloadList.removeLast();
    downloadNext();
  }
}

} // namespace QtPlugins
} // namespace Avogadro
