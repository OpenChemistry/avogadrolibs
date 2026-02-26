/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "packagemanagerdialog.h"
#include "packagemodel.h"
#include "ui_packagemanagerdialog.h"
#include "zipextracter.h"

#include <avogadro/qtgui/packagemanager.h>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QStandardPaths>

#include <QtWidgets/QFileDialog>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableView>

#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>

#include <QtCore/QSortFilterProxyModel>

#include <nlohmann/json.hpp>

namespace Avogadro::QtPlugins {

static void setRawHeaders(QNetworkRequest* request)
{
  request->setRawHeader("Accept", "text/html,application/xhtml+xml,application/"
                                  "xml;q=0.9,image/webp,*/*;q=0.8");
  request->setRawHeader("User-Agent",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/54.0.2840.71 Safari/537.36");
  request->setRawHeader("Accept-Language", "en-US,en;q=0.8");
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

PackageManagerDialog::PackageManagerDialog(QWidget* parent)
  : QDialog(parent), m_ui(new Ui::PackageManagerDialog)
{
  m_filePath =
    QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) +
    QStringLiteral("/packages");

  m_ui->setupUi(this);
  m_network = new QNetworkAccessManager(this);

  m_model = new PackageModel(this);
  m_proxyModel = new QSortFilterProxyModel(this);
  m_proxyModel->setSourceModel(m_model);
  m_proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
  m_proxyModel->setFilterKeyColumn(-1); // search all columns

  m_ui->packageTable->setModel(m_proxyModel);
  m_ui->packageTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_ui->packageTable->horizontalHeader()->setStretchLastSection(true);
  m_ui->packageTable->horizontalHeader()->setSectionResizeMode(
    QHeaderView::ResizeToContents);
  m_ui->packageTable->verticalHeader()->hide();

  connect(m_ui->searchEdit, &QLineEdit::textChanged, m_proxyModel,
          &QSortFilterProxyModel::setFilterFixedString);
  connect(m_ui->refreshButton, &QPushButton::clicked, this,
          &PackageManagerDialog::refreshOnlineCatalog);
  connect(m_ui->packageTable, &QTableView::clicked, this,
          &PackageManagerDialog::onTableClicked);
  connect(m_ui->installButton, &QPushButton::clicked, this,
          &PackageManagerDialog::installSelected);
  connect(m_ui->removeButton, &QPushButton::clicked, this,
          &PackageManagerDialog::removeSelected);
  connect(m_ui->installLocalButton, &QPushButton::clicked, this,
          &PackageManagerDialog::installFromDirectory);
  connect(QtGui::PackageManager::instance(),
          &QtGui::PackageManager::packagesInstalled, this,
          &PackageManagerDialog::onPackagesInstalled);

  // Load installed packages immediately (without waiting for the network)
  m_model->mergeInstalledPackages();
  // Then fetch the online catalog
  getRepoData();
}

PackageManagerDialog::~PackageManagerDialog()
{
  delete m_ui;
}

// ---------------------------------------------------------------------------
// Online catalog
// ---------------------------------------------------------------------------

void PackageManagerDialog::getRepoData(const QString& url)
{
  QNetworkRequest request;
  setRawHeaders(&request);
  request.setUrl(QUrl(url));
  QNetworkReply* reply = m_network->get(request);
  connect(reply, &QNetworkReply::finished, this,
          &PackageManagerDialog::onCatalogReply);
}

void PackageManagerDialog::refreshOnlineCatalog()
{
  m_ui->readmeBrowser->clear();
  getRepoData();
}

void PackageManagerDialog::onCatalogReply()
{
  auto* reply = qobject_cast<QNetworkReply*>(sender());
  if (reply == nullptr)
    return;

  if (reply->error() != QNetworkReply::NoError) {
    m_ui->readmeBrowser->append(
      tr("Error downloading package list: %1").arg(reply->errorString()));
    reply->deleteLater();
    return;
  }

  QByteArray bytes = reply->readAll();
  reply->deleteLater();

  if (bytes.isEmpty()) {
    m_ui->readmeBrowser->append(tr("Error: empty response from server."));
    return;
  }

  m_model->loadOnlineCatalog(bytes);
  m_model->mergeInstalledPackages();
}

// ---------------------------------------------------------------------------
// README display
// ---------------------------------------------------------------------------

void PackageManagerDialog::onTableClicked(const QModelIndex& proxyIndex)
{
  if (!proxyIndex.isValid())
    return;

  // Handle checkbox toggle on status column
  QModelIndex sourceIndex = m_proxyModel->mapToSource(proxyIndex);
  int row = sourceIndex.row();

  if (proxyIndex.column() == PackageModel::StatusColumn) {
    bool current = m_model->entry(row).checked;
    m_model->setChecked(row, !current);
    return;
  }

  // Fetch README for the clicked row
  QString url = m_model->readmeUrl(row);
  if (url.isEmpty())
    return;

  m_ui->readmeBrowser->clear();
  QNetworkRequest request;
  setRawHeaders(&request);
  request.setUrl(QUrl(url));
  QNetworkReply* reply = m_network->get(request);
  connect(reply, &QNetworkReply::finished, this,
          &PackageManagerDialog::onReadmeReply);
}

void PackageManagerDialog::onReadmeReply()
{
  auto* reply = qobject_cast<QNetworkReply*>(sender());
  if (reply == nullptr)
    return;

  if (reply->error() != QNetworkReply::NoError) {
    reply->deleteLater();
    return;
  }

  QByteArray bytes = reply->readAll();
  reply->deleteLater();

  // GitHub API returns JSON with base64-encoded content
  if (!nlohmann::json::accept(bytes.data()))
    return;

  nlohmann::json root = nlohmann::json::parse(bytes.data());
  if (root.contains("content") && root["content"].is_string()) {
    QByteArray content =
      QByteArray::fromBase64(root["content"].get<std::string>().c_str());
    m_ui->readmeBrowser->setMarkdown(QString::fromUtf8(content));
  }
}

// ---------------------------------------------------------------------------
// Install / Update
// ---------------------------------------------------------------------------

void PackageManagerDialog::installSelected()
{
  m_downloadQueue.clear();
  m_ui->readmeBrowser->clear();

  const QList<int> rows = m_model->checkedRows();
  for (int row : rows) {
    const PackageModel::PackageEntry& e = m_model->entry(row);
    if (e.zipballUrl.isEmpty())
      continue;
    DownloadEntry de;
    de.url = e.zipballUrl;
    de.name = e.name;
    m_downloadQueue.append(de);
  }

  if (m_downloadQueue.isEmpty()) {
    QMessageBox::information(
      this, tr("Nothing Selected"),
      tr("Check the box next to a package to install or update it."));
    return;
  }

  downloadNext();
}

void PackageManagerDialog::downloadNext()
{
  if (m_downloadQueue.isEmpty())
    return;

  const QString url = m_downloadQueue.last().url;
  QNetworkRequest request;
  setRawHeaders(&request);
  request.setUrl(QUrl(url));
  QNetworkReply* reply = m_network->get(request);
  connect(reply, &QNetworkReply::finished, this,
          &PackageManagerDialog::handleRedirect);
}

void PackageManagerDialog::handleRedirect()
{
  auto* reply = qobject_cast<QNetworkReply*>(sender());
  if (reply == nullptr)
    return;
  if (m_downloadQueue.isEmpty()) {
    reply->deleteLater();
    return;
  }

  int statusCode =
    reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

  if (reply->error() == QNetworkReply::NoError) {
    if (statusCode == 301 || statusCode == 302 || statusCode == 307 ||
        statusCode == 308) {
      QUrl redirectUrl =
        reply->attribute(QNetworkRequest::RedirectionTargetAttribute).toUrl();
      if (redirectUrl.isRelative())
        redirectUrl = reply->url().resolved(redirectUrl);
      reply->deleteLater();

      if (!redirectUrl.isValid()) {
        m_ui->readmeBrowser->append(
          tr("Failed to follow redirect while downloading %1.\n")
            .arg(m_downloadQueue.last().name));
        m_downloadQueue.removeLast();
        downloadNext();
        return;
      }

      QNetworkRequest request;
      setRawHeaders(&request);
      request.setUrl(redirectUrl);
      QNetworkReply* redirectReply = m_network->get(request);
      connect(redirectReply, &QNetworkReply::finished, this,
              &PackageManagerDialog::handleRedirect);
    } else if (statusCode == 200) {
      unzipPlugin(reply);
    } else {
      m_ui->readmeBrowser->append(
        tr("Failed to download from %1: status %2, %3\n")
          .arg(reply->url().toString())
          .arg(statusCode)
          .arg(reply->errorString()));
      reply->deleteLater();
      m_downloadQueue.removeLast();
      downloadNext();
    }
  } else {
    m_ui->readmeBrowser->append(tr("Failed to download from %1: %2\n")
                                  .arg(reply->url().toString())
                                  .arg(reply->errorString()));
    reply->deleteLater();
    m_downloadQueue.removeLast();
    downloadNext();
  }
}

void PackageManagerDialog::unzipPlugin(QNetworkReply* reply)
{
  if (reply == nullptr)
    return;
  if (m_downloadQueue.isEmpty()) {
    reply->deleteLater();
    return;
  }

  if (reply->error() != QNetworkReply::NoError) {
    reply->deleteLater();
    m_downloadQueue.removeLast();
    downloadNext();
    return;
  }

  QByteArray fileData = reply->readAll();
  reply->deleteLater();

  QDir().mkpath(m_filePath);

  const QString repoName = m_downloadQueue.last().name;
  const QString filename = repoName + QStringLiteral(".zip");
  const QString absolutePath = m_filePath + '/' + filename;

  m_ui->readmeBrowser->append(
    tr("Downloading %1 to %2\n").arg(filename).arg(m_filePath));

  QFile out(absolutePath);
  if (!out.open(QIODevice::WriteOnly)) {
    QMessageBox::critical(this, tr("Error"),
                          tr("Cannot save file %1.").arg(absolutePath));
    m_downloadQueue.removeLast();
    downloadNext();
    return;
  }
  out.write(fileData);
  out.close();

  ZipExtracter unzip;
  m_ui->readmeBrowser->append(tr("Extracting %1…\n").arg(filename));

  QList<QString> newFiles = unzip.listFiles(absolutePath.toStdString());
  QList<QString> errors =
    unzip.extract(m_filePath.toStdString(), absolutePath.toStdString());

  if (errors.empty() && !newFiles.isEmpty()) {
    m_ui->readmeBrowser->append(
      tr("Extraction complete (%1 files)\n").arg(newFiles.size()));

    // Derive component name: "OpenChemistry-crystals-a7c672d" → "crystals"
    QStringList namePieces = newFiles[0].split('-');
    if (namePieces.size() >= 3) {
      namePieces.removeLast();
      namePieces.removeFirst();
    } else if (namePieces.size() == 2) {
      namePieces.removeFirst();
    }
    const QString component = namePieces.join('-');
    const QString destination = m_filePath + '/' + component;

    QDir prev(destination);
    if (prev.exists())
      prev.removeRecursively();

    QDir().rename(m_filePath + '/' + newFiles[0], destination);
    QtGui::PackageManager::instance()->installPackages({ destination });
  } else {
    if (!errors.isEmpty())
      m_ui->readmeBrowser->append(
        tr("Extraction error: %1").arg(errors.first()));
    else
      m_ui->readmeBrowser->append(tr("Extraction yielded no files.\n"));
  }

  out.remove();
  m_downloadQueue.removeLast();
  downloadNext();
}

void PackageManagerDialog::onPackagesInstalled()
{
  m_ui->readmeBrowser->append(tr("Installation complete.\n"));
  m_model->mergeInstalledPackages();
  m_model->uncheckAll();
}

// ---------------------------------------------------------------------------
// Remove
// ---------------------------------------------------------------------------

void PackageManagerDialog::removeSelected()
{
  // Collect installed checked rows (map proxy → source)
  QList<int> toRemove;
  for (int i = 0; i < m_model->entryCount(); ++i) {
    const PackageModel::PackageEntry& e = m_model->entry(i);
    if (e.checked && e.status != PackageModel::PackageStatus::NotInstalled) {
      toRemove.append(i);
    }
  }

  if (toRemove.isEmpty()) {
    QMessageBox::information(
      this, tr("Nothing to Remove"),
      tr("Check the box next to an installed package to remove it."));
    return;
  }

  // Ask user whether to delete files
  QMessageBox msgBox(this);
  msgBox.setWindowTitle(tr("Remove Packages"));
  msgBox.setText(tr("Remove %n selected package(s)?", "", toRemove.size()));
  msgBox.setIcon(QMessageBox::Question);
  msgBox.setStandardButtons(QMessageBox::Cancel);

  msgBox.addButton(tr("Keep Files on Disk"), QMessageBox::NoRole);
  QPushButton* deleteBtn = msgBox.addButton(tr("Delete Files from Disk"),
                                            QMessageBox::DestructiveRole);

  msgBox.exec();

  if (msgBox.clickedButton() == msgBox.button(QMessageBox::Cancel))
    return;

  bool deleteFiles = (msgBox.clickedButton() == deleteBtn);

  for (int row : toRemove) {
    PackageModel::PackageEntry& e = m_model->entry(row);
    const QString packageKey = e.packageKey.isEmpty() ? e.name : e.packageKey;
    QtGui::PackageManager::instance()->unregisterPackage(packageKey);
    if (deleteFiles && !e.installedDir.isEmpty())
      QDir(e.installedDir).removeRecursively();
  }

  // Refresh table state
  m_model->mergeInstalledPackages();
  m_model->uncheckAll();
}

// ---------------------------------------------------------------------------
// Install from local directory
// ---------------------------------------------------------------------------

void PackageManagerDialog::installFromDirectory()
{
  QString dir = QFileDialog::getExistingDirectory(
    this, tr("Select Package Directory"), QDir::homePath());
  if (dir.isEmpty())
    return;

  if (!QFileInfo(dir + QStringLiteral("/pyproject.toml")).exists()) {
    QMessageBox::warning(
      this, tr("Invalid Directory"),
      tr("The selected directory does not contain a pyproject.toml file."));
    return;
  }

  QDir().mkpath(m_filePath);

  const QString baseName = QFileInfo(dir).fileName();
  const QString linkPath = m_filePath + '/' + baseName;

  // Remove any previous installation at that path
  QFileInfo existing(linkPath);
  if (existing.isSymLink() || existing.isDir())
    QDir(linkPath).removeRecursively();

  // Attempt to create a symlink; fall back to a recursive copy
  bool linked = QFile::link(dir, linkPath);
  if (linked) {
    m_ui->readmeBrowser->append(
      tr("Created symlink: %1 → %2\n").arg(linkPath).arg(dir));
  } else {
    m_ui->readmeBrowser->append(
      tr("Symlink creation failed; copying files instead…\n"));
    if (!copyDir(dir, linkPath)) {
      QMessageBox::critical(this, tr("Error"),
                            tr("Failed to copy package to %1.").arg(linkPath));
      return;
    }
  }

  m_ui->readmeBrowser->append(tr("Installing package from %1…\n").arg(dir));
  QtGui::PackageManager::instance()->installPackages({ linkPath });
}

bool PackageManagerDialog::copyDir(const QString& src, const QString& dst)
{
  QDir srcDir(src);
  if (!srcDir.exists())
    return false;

  QDir().mkpath(dst);

  const QFileInfoList entries =
    srcDir.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);
  for (const QFileInfo& fi : entries) {
    const QString target = dst + '/' + fi.fileName();
    if (fi.isDir()) {
      if (!copyDir(fi.absoluteFilePath(), target))
        return false;
    } else {
      if (!QFile::copy(fi.absoluteFilePath(), target))
        return false;
    }
  }
  return true;
}

} // namespace Avogadro::QtPlugins
