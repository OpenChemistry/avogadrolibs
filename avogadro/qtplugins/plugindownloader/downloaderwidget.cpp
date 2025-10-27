/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "downloaderwidget.h"
#include "ui_downloaderwidget.h"
#include "zipextracter.h"

#include <avogadro/qtgui/utilities.h>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QProcess>
#include <QtCore/QRegularExpression>
#include <QtCore/QSettings>
#include <QtCore/QStandardPaths>

#include <QtWidgets/QGraphicsRectItem>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTableWidgetItem>

#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>

using json = nlohmann::json;

namespace Avogadro::QtPlugins {

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
    QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
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

    // quick check that it's not empty
    if (bytes.isEmpty()) {
      QMessageBox::warning(this, tr("Error"),
                           tr("Error downloading plugin data."));
      return;
    }
    // does it parse as JSON cleanly?
    if (!json::accept(bytes.data())) {
      QMessageBox::warning(this, tr("Error"), tr("Error parsing plugin data."));
      return;
    }

    // parse the json
    m_root = json::parse(bytes.data());
    int numRepos = m_root.size();
    m_ui->repoTable->setRowCount(numRepos);
    m_repoList.clear();
    for (int i = 0; i < numRepos; i++) {
      m_repoList.emplace_back();

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

      auto* checkbox = new QTableWidgetItem();
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
void DownloaderWidget::downloadREADME(int row, [[maybe_unused]] int col)
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

bool DownloaderWidget::checkToInstall()
{
  QSettings settings;

  // check if we've asked the user before
  bool neverInstall =
    settings.value("neverInstallRequirements", false).toBool();
  if (neverInstall)
    return false;

  bool alwaysInstall =
    settings.value("alwaysInstallRequirements", false).toBool();
  if (alwaysInstall)
    return true;

  // okay, ask the user before installing
  QMessageBox msgBox;
  msgBox.setText(tr("This plugin requires certain packages to be installed.\n"
                    "Do you want to install them?"));
  msgBox.setIcon(QMessageBox::Question);
  msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
  msgBox.setDefaultButton(QMessageBox::Yes);

  // add buttons for "Yes Always" and "No, Never"
  QPushButton* yesAlwaysButton =
    msgBox.addButton(tr("Always"), QMessageBox::YesRole);
  QPushButton* neverButton = msgBox.addButton(tr("Never"), QMessageBox::NoRole);
  msgBox.exec();

  if (msgBox.clickedButton() == yesAlwaysButton) {
    settings.setValue("alwaysInstallRequirements", true);
    return true;
  } else if (msgBox.clickedButton() == neverButton) {
    settings.setValue("neverInstallRequirements", true);
    return false;
  } else if (msgBox.clickedButton() == msgBox.button(QMessageBox::Yes)) {
    return true;
  } else {
    return false;
  }
}

// The download url for Github is always a redirect to the actual zip
// Using Qt 6 the redirect gets taken care of automatically, but on Qt 5 we
// have to do it manually
// m_reply is a QNetworkReply
void DownloaderWidget::handleRedirect()
{
  int statusCode =
    m_reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
  if (m_reply->error() == QNetworkReply::NoError) {
    if (statusCode == 302) {
      // Redirected, have to manually redirect
      QVariant possibleRedirectUrl =
        m_reply->attribute(QNetworkRequest::RedirectionTargetAttribute);
      QUrl _urlRedirectedTo = possibleRedirectUrl.toUrl();
      QNetworkRequest request;
      setRawHeaders(&request);
      request.setUrl(_urlRedirectedTo); // Set the url
      m_reply = m_NetworkAccessManager->get(request);
      // Now we have the actual zip and can extract it
      connect(m_reply, SIGNAL(finished()), this, SLOT(unzipPlugin()));
    } else if (statusCode == 200) {
      // Normal success response
      unzipPlugin();
    } else {
      // Something went wrong
      QString errorString = m_reply->errorString();
      m_ui->readmeBrowser->append(
        tr("Failed to download from %1: status code %2, %3\n",
           "After an HTTP request; %1 is a URL, %2 is the HTTP status code, %3 "
           "is the error message (if any)")
          .arg(m_reply->url().toString())
          .arg(statusCode)
          .arg(errorString));
    }
  } else {
    QString errorString = m_reply->errorString();
    m_ui->readmeBrowser->append(
      tr("Failed to download from %1: status code %2, %3\n",
         "After an HTTP request; %1 is a URL, %2 is the HTTP status code, %3 "
         "is the error message (if any)")
        .arg(m_reply->url().toString())
        .arg(statusCode)
        .arg(errorString));
    m_reply->deleteLater();
    m_downloadList.removeLast();
    downloadNext();
  }
}

// Save and unzip the plugin zipball
void DownloaderWidget::unzipPlugin()
{
  if (m_reply->error() != QNetworkReply::NoError) {
    return;
  }

  // get the downloaded file
  QByteArray fileData = m_reply->readAll();
  QDir().mkpath(m_filePath);

  QString repoName = m_downloadList.last().name;
  QString filename = repoName + ".zip";
  QString absolutePath = m_filePath + "/" + filename;
  // something like /path/to/avogadro/commands or formats/ etc.
  QString extractDirectory =
    m_filePath + "/" + m_downloadList.last().type + "/";

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
  m_ui->readmeBrowser->append(tr("Finished %1 files\n").arg(newFiles.length()));

  QList<QString> ret = unzip.extract(extractdir, absolutep);
  if (ret.empty()) {
    m_ui->readmeBrowser->append(tr("Extraction successful\n"));

    // we should have multiple files or we grabbed an empty zip
    if (newFiles.length() > 0) {
      // Extract component name and handle previous version
      // e.g. we extracted to a path like User-Repo-GitHash
      //     OpenChemistry-crystals-a7c672d
      // we want to check for OpenChemistry-crystals
      QStringList namePieces = newFiles[0].split('-');
      if (namePieces.length() >= 3) {
        namePieces.removeLast();
        namePieces.removeFirst();
      } else if (namePieces.length() == 2) {
        // remove the organization
        namePieces.removeFirst();
      }

      QString component = namePieces.join('-');
      QString destination(extractDirectory + '/' + component);

      // Remove previous version if it's present
      QDir previousInstall(destination);
      if (previousInstall.exists())
        previousInstall.removeRecursively();

      // move our new directory in place
      QDir().rename(extractDirectory + '/' + newFiles[0], destination);

      // Handle dependency installation
      // look for requirements.txt or environment.yml or pyproject.toml
      // and use pixi, conda or pip to install
      QString requirementFile = findRequirementFile(destination);
      if (!requirementFile.isEmpty() && checkToInstall()) {
        QString pixiPath = QtGui::Utilities::findExecutablePath("pixi");

        if (!pixiPath.isEmpty()) {
          installWithPixi(requirementFile);
        } else {
          QSettings settings;
          QString condaEnv = settings.value("condaEnvironment").toString();
          QString condaPath = settings.value("condaPath").toString();

          if (!condaEnv.isEmpty() && !condaPath.isEmpty()) {
            installWithConda(requirementFile);
          } else {
            installWithPip(requirementFile);
          }
        }
      } // end install requirements
    }   // we have new files
  } else {
    m_ui->readmeBrowser->append(
      tr("Error while extracting: %1").arg(ret.first()));
  }

  out.remove();
  m_reply->deleteLater();
  m_downloadList.removeLast();
  downloadNext();
}

// Find the first requirement file that exists
// prefer pyproject.toml over other options
QString DownloaderWidget::findRequirementFile(const QString& destination)
{
  QStringList requirementFiles = {
    destination + "/pyproject.toml",
    destination + "/requirements.txt",
    destination + "/environment.yml",
  };

  for (const QString& file : requirementFiles) {
    if (QFile::exists(file)) {
      return file;
    }
  }

  return QString(); // Return empty string if no requirement file found
}

// Install dependencies using pixi
void DownloaderWidget::installWithPixi(const QString& requirementFile)
{
  m_progressDialog = new QProgressDialog(
    tr("Installing dependencies with %1…", "argument is program name")
      .arg("pixi"),
    tr("Cancel"), 0, 0, this);
  m_progressDialog->setWindowModality(Qt::WindowModal);

  connect(m_progressDialog, SIGNAL(canceled()), this,
          SLOT(cancelInstallation()));

  QStringList arguments;
  m_installerProcess = new QProcess(this);
  m_installerProcess->setWorkingDirectory(m_filePath);
  QString pixiPath = QtGui::Utilities::findExecutablePath("pixi");
  m_progressDialog->show();

  // first check if there's already a pyproject.toml
  if (!requirementFile.contains("pyproject.toml")) {
    // we have to pixi init first to create a pyproject.toml
    arguments << "init"
              << "."
              << "--format"
              << "pyproject";
    m_installerProcess->start(pixiPath, arguments);
    m_installerProcess->waitForFinished();

    if (requirementFile.contains("requirements.txt")) {
      // pixi import --format=pypi-txt --feature=default requirements.txt
      arguments.clear();
      arguments << "import"
                << "--format=pypi-txt"
                << "--feature=default"
                << "requirements.txt";
      m_installerProcess->start(pixiPath, arguments);
      m_installerProcess->waitForFinished();
    } else if (requirementFile.contains("environment.yml")) {
      // pixi import --format=conda environment.yml
      arguments.clear();
      arguments << "import"
                << "--format=conda-env"
                << "environment.yml";
      m_installerProcess->start(pixiPath, arguments);
      m_installerProcess->waitForFinished();
    }
  }

  // install everything
  arguments.clear();
  arguments << "install";

  connect(m_installerProcess, SIGNAL(finished(int, QProcess::ExitStatus)), this,
          SLOT(installationFinished()));

  m_installerProcess->start(pixiPath, arguments);
}

// Install dependencies using conda
void DownloaderWidget::installWithConda(const QString& requirementFile)
{
  if (requirementFile.isEmpty() || requirementFile.contains("pyproject.toml")) {
    installWithPip(requirementFile);
    return; // pyproject.toml not supported by conda
  }

  m_progressDialog = new QProgressDialog(
    tr("Installing dependencies with %1…", "argument is program name")
      .arg("conda"),
    tr("Cancel"), 0, 0, this);
  m_progressDialog->setWindowModality(Qt::WindowModal);

  connect(m_progressDialog, SIGNAL(canceled()), this,
          SLOT(cancelInstallation()));

  QSettings settings;
  QString condaPath = settings.value("condaPath").toString();
  QString condaEnv = settings.value("condaEnvironment").toString();

  QStringList arguments;
  arguments << "install"
            << "-y"
            << "-c"
            << "conda-forge"
            << "--file" << requirementFile << "-n" << condaEnv;

  m_installerProcess = new QProcess(this);

  connect(m_installerProcess, SIGNAL(finished(int, QProcess::ExitStatus)), this,
          SLOT(installationFinished()));

  m_progressDialog->show();
  m_installerProcess->start(condaPath, arguments);
}

// Install dependencies using pip
void DownloaderWidget::installWithPip(const QString& requirementFile)
{
  if (requirementFile.isEmpty() ||
      requirementFile.contains("environment.yml")) {
    return; // nothing to do, please migrate to pyproject.toml
  }

  m_progressDialog = new QProgressDialog(
    tr("Installing dependencies with %1…", "argument is program name")
      .arg("pip"),
    tr("Cancel"), 0, 0, this);
  m_progressDialog->setWindowModality(Qt::WindowModal);

  connect(m_progressDialog, SIGNAL(canceled()), this,
          SLOT(cancelInstallation()));

  QSettings settings;
  QString pythonPath =
    settings.value("interpreters/python", "python").toString();

  QStringList arguments;
  arguments << "-m"
            << "pip"
            << "install"
            << ".";

  m_installerProcess = new QProcess(this);
  m_installerProcess->setWorkingDirectory(m_filePath);

  connect(m_installerProcess, SIGNAL(finished(int, QProcess::ExitStatus)), this,
          SLOT(installationFinished()));

  m_progressDialog->show();
  m_installerProcess->start(pythonPath, arguments);
}

// Called when installation process finishes
void DownloaderWidget::installationFinished()
{
  m_progressDialog->close();
  m_progressDialog->deleteLater();

  QString output(m_installerProcess->readAllStandardOutput());
  QString error(m_installerProcess->readAllStandardError());

  if (!output.isEmpty())
    m_ui->readmeBrowser->append(output);
  if (!error.isEmpty())
    m_ui->readmeBrowser->append(error);

  m_installerProcess->deleteLater();
  m_installerProcess = nullptr;
}

// Called when user clicks Cancel on the progress dialog
void DownloaderWidget::cancelInstallation()
{
  if (m_installerProcess && m_installerProcess->state() == QProcess::Running) {
    m_ui->readmeBrowser->append(tr("Installation canceled\n"));
    m_installerProcess->kill();
    m_installerProcess->deleteLater();
    m_installerProcess = nullptr;
  }

  m_progressDialog->close();
  m_progressDialog->deleteLater();
}

} // namespace Avogadro::QtPlugins
