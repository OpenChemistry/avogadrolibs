/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "packagemanagerdialog.h"
#include "packagemodel.h"
#include "ui_packagemanagerdialog.h"
#include "zipextractor.h"

#include <avogadro/qtgui/packagemanager.h>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QItemSelectionModel>
#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QStandardPaths>

#include <QtGui/QCursor>

#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>

#include <QtWidgets/QApplication>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableView>
#include <QtWidgets/QToolTip>

#include <nlohmann/json.hpp>

namespace Avogadro::QtPlugins {

static void setRawHeaders(QNetworkRequest* request)
{
  request->setRawHeader("Accept", "text/html,application/xhtml+xml,application/"
                                  "xml;q=0.9,image/webp,*/*;q=0.8");
  request->setRawHeader("User-Agent", "Avogadro/2.0 PackageManager");
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
    QStringLiteral("/plugins");

  m_ui->setupUi(this);
  m_network = new QNetworkAccessManager(this);

  m_model = new PackageModel(this);
  m_proxyModel = new QSortFilterProxyModel(this);
  m_proxyModel->setSourceModel(m_model);
  m_proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
  m_proxyModel->setFilterKeyColumn(-1); // search all columns

  m_ui->packageTable->setModel(m_proxyModel);
  m_ui->packageTable->setMouseTracking(true);
  m_ui->packageTable->viewport()->setMouseTracking(true);
  m_ui->packageTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_ui->packageTable->horizontalHeader()->setStretchLastSection(true);
  m_ui->packageTable->horizontalHeader()->setSectionResizeMode(
    QHeaderView::ResizeToContents);
  m_ui->packageTable->verticalHeader()->hide();

  connect(m_ui->searchEdit, &QLineEdit::textChanged, m_proxyModel,
          &QSortFilterProxyModel::setFilterFixedString);
  connect(m_ui->refreshButton, &QPushButton::clicked, this,
          &PackageManagerDialog::refreshOnlineCatalog);
  connect(m_ui->packageTable->selectionModel(),
          &QItemSelectionModel::currentRowChanged, this,
          &PackageManagerDialog::onCurrentRowChanged);
  connect(m_ui->packageTable, &QAbstractItemView::entered, this,
          &PackageManagerDialog::showCellTooltip);
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
      tr("Error downloading plugin list: %1").arg(reply->errorString()));
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

void PackageManagerDialog::showCellTooltip(const QModelIndex& proxyIndex)
{
  const QString tooltip =
    m_proxyModel->data(proxyIndex, Qt::ToolTipRole).toString();
  m_ui->packageTable->viewport()->setToolTip(tooltip);

  if (tooltip.isEmpty()) {
    QToolTip::hideText();
    return;
  }

  int pointSize = QApplication::font().pointSize();
  if (pointSize <= 0)
    pointSize = 10;
  ++pointSize;

  QString html = tooltip.toHtmlEscaped();
  html.replace(QLatin1Char('\n'), QStringLiteral("<br/>"));

  QToolTip::showText(QCursor::pos(),
                     QStringLiteral("<span style=\"font-size:%1pt;\">%2</span>")
                       .arg(pointSize)
                       .arg(html),
                     m_ui->packageTable->viewport(),
                     m_ui->packageTable->visualRect(proxyIndex));
}

void PackageManagerDialog::onCurrentRowChanged(const QModelIndex& current,
                                               const QModelIndex& previous)
{
  Q_UNUSED(previous)
  if (!current.isValid())
    return;

  QModelIndex sourceIndex = m_proxyModel->mapToSource(current);
  QString url = m_model->readmeUrl(sourceIndex.row());
  if (url.isEmpty())
    return;

  m_ui->readmeBrowser->clear();
  QNetworkRequest request;
  setRawHeaders(&request);
  request.setUrl(QUrl(url));
  request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                       QNetworkRequest::NoLessSafeRedirectPolicy);
  QNetworkReply* reply = m_network->get(request);
  reply->setProperty("readmeUrl", url);
  connect(reply, &QNetworkReply::finished, this,
          &PackageManagerDialog::onReadmeReply);
}

void PackageManagerDialog::onReadmeReply()
{
  auto* reply = qobject_cast<QNetworkReply*>(sender());
  if (reply == nullptr)
    return;

  // Discard replies that no longer match the current selection
  const QString requestedUrl = reply->property("readmeUrl").toString();
  const QModelIndex currentIdx =
    m_ui->packageTable->selectionModel()->currentIndex();
  if (currentIdx.isValid()) {
    const QModelIndex sourceIdx = m_proxyModel->mapToSource(currentIdx);
    if (requestedUrl != m_model->readmeUrl(sourceIdx.row())) {
      reply->deleteLater();
      return;
    }
  }

  if (reply->error() != QNetworkReply::NoError) {
    m_ui->readmeBrowser->setPlainText(
      tr("Error fetching README: %1").arg(reply->errorString()));
    reply->deleteLater();
    return;
  }

  QByteArray bytes = reply->readAll();
  reply->deleteLater();

  // GitHub API returns JSON with base64-encoded content
  if (nlohmann::json::accept(bytes.data())) {
    nlohmann::json root = nlohmann::json::parse(bytes.data());
    if (root.contains("content") && root["content"].is_string()) {
      QByteArray content =
        QByteArray::fromBase64(root["content"].get<std::string>().c_str());
      m_ui->readmeBrowser->setMarkdown(QString::fromUtf8(content));
      return;
    }
  }

  // Fall back: treat the response as raw markdown
  m_ui->readmeBrowser->setMarkdown(QString::fromUtf8(bytes));
}

// ---------------------------------------------------------------------------
// Install / Update
// ---------------------------------------------------------------------------

void PackageManagerDialog::installSelected()
{
  m_downloadQueue.clear();
  m_ui->readmeBrowser->clear();

  QList<int> rows = m_model->checkedRows();
  if (rows.isEmpty()) {
    // Fall back to the view's selected (highlighted) rows
    const QModelIndexList selected =
      m_ui->packageTable->selectionModel()->selectedRows();
    for (const QModelIndex& proxyIdx : selected)
      rows.append(m_proxyModel->mapToSource(proxyIdx).row());
  }
  if (rows.isEmpty()) {
    QMessageBox::information(
      this, tr("Nothing Selected"),
      tr("Check the box next to a plugin to install or update it."));
    return;
  }

  // Warn about any packages that require a newer Avogadro version
  QStringList incompatible;
  for (int row : rows) {
    const PackageModel::PackageEntry& e = m_model->entry(row);
    if (!PackageModel::versionCompatible(e))
      incompatible.append(
        tr("%1 (requires %2)").arg(e.name, e.minimumAvogadroVersion));
  }
  if (!incompatible.isEmpty()) {
    const int ret = QMessageBox::warning(
      this, tr("Version Incompatibility"),
      tr("The following plugins require a newer version of Avogadro:\n\n"
         "%1\n\nInstall anyway?")
        .arg(incompatible.join('\n')),
      QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
    if (ret != QMessageBox::Yes)
      return;
  }

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
    QStringList unavailable;
    unavailable.reserve(rows.size());
    for (int row : rows) {
      const PackageModel::PackageEntry& e = m_model->entry(row);
      if (e.zipballUrl.isEmpty())
        unavailable.append(e.name);
    }
    QMessageBox::information(
      this, tr("No Download Available"),
      tr("The selected plugin(s) do not provide a downloadable source URL:\n\n"
         "%1")
        .arg(unavailable.join(QLatin1Char('\n'))));
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

  ZipExtractor unzip;
  m_ui->readmeBrowser->append(tr("Extracting %1…\n").arg(filename));

  QList<QString> newFiles = unzip.listFiles(absolutePath.toStdString());
  QList<QString> errors =
    unzip.extract(m_filePath.toStdString() + '/', absolutePath.toStdString());

  if (errors.empty() && !newFiles.isEmpty()) {
    m_ui->readmeBrowser->append(
      tr("Extraction complete (%1 files)\n").arg(newFiles.size()));

    // Derive component name: "OpenChemistry-crystals-a7c672d" → "crystals"
    // Trim trailing '/', then take the substring between the first and last '-'
    QString rawName = newFiles[0];
    if (rawName.endsWith('/'))
      rawName.chop(1);
    const int firstDash = rawName.indexOf('-');
    const int lastDash = rawName.lastIndexOf('-');
    const QString component =
      (firstDash != -1 && lastDash > firstDash)
        ? rawName.mid(firstDash + 1, lastDash - firstDash - 1)
        : rawName;
    const QString source = QDir::cleanPath(m_filePath + '/' + newFiles[0]);
    const QString dest = QDir::cleanPath(m_filePath + '/' + component);

    if (source != dest) {
      QDir(dest).removeRecursively();

      if (!QDir().rename(source, dest)) {
        m_ui->readmeBrowser->append(
          tr("Error: could not move extracted package %1 to %2\n")
            .arg(source)
            .arg(dest));
        out.remove();
        m_downloadQueue.removeLast();
        downloadNext();
        return;
      }
    }
    QtGui::PackageManager::instance()->installPackages({ dest });
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

  // Symlinks are created for local-disk installs — just remove the link
  QMutableListIterator<int> it(toRemove);
  while (it.hasNext()) {
    int row = it.next();
    const PackageModel::PackageEntry& e = m_model->entry(row);
    QFileInfo fi(e.installedDir);
    if (fi.isSymLink()) {
      QFile::remove(e.installedDir);
      const QString packageKey = e.packageKey.isEmpty() ? e.name : e.packageKey;
      QtGui::PackageManager::instance()->unregisterPackage(packageKey);
      it.remove();
    }
  }

  if (toRemove.isEmpty()) {
    // Fall back to the view's selected (highlighted) rows
    const QModelIndexList selected =
      m_ui->packageTable->selectionModel()->selectedRows();
    for (const QModelIndex& proxyIdx : selected) {
      int row = m_proxyModel->mapToSource(proxyIdx).row();
      const PackageModel::PackageEntry& e = m_model->entry(row);
      if (e.status != PackageModel::PackageStatus::NotInstalled)
        toRemove.append(row);
    }
  }

  if (toRemove.isEmpty()) {
    QMessageBox::information(
      this, tr("Nothing to Remove"),
      tr("Check the box next to an installed plugin to remove it."));
    return;
  }

  // Ask user whether to delete files
  QMessageBox msgBox(this);
  msgBox.setWindowTitle(tr("Remove Plugins"));
  msgBox.setText(tr("Remove %n selected plugin(s)?", "", toRemove.size()));
  msgBox.setIcon(QMessageBox::Question);
  msgBox.setStandardButtons(QMessageBox::Cancel);

  msgBox.addButton(tr("Keep Files"), QMessageBox::NoRole);
  QPushButton* deleteBtn =
    msgBox.addButton(tr("Delete Files"), QMessageBox::DestructiveRole);

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
    this, tr("Select Plugin Directory"), QDir::homePath());
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

  QFileInfo existing(linkPath);
  if (existing.isSymLink()) {
    if (existing.symLinkTarget() == dir) {
      // Already pointing at the right directory — nothing to do
      m_ui->readmeBrowser->append(
        tr("Plugin already installed as symlink: %1\n").arg(linkPath));
      QtGui::PackageManager::instance()->installPackages({ linkPath });
      return;
    }
    // Stale symlink pointing elsewhere — remove and reinstall
    QFile::remove(linkPath);
  } else if (existing.isDir()) {
    // Remove any previous non-symlink installation at that path
    QDir(linkPath).removeRecursively();
  }

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

  m_ui->readmeBrowser->append(tr("Installing plugin from %1…\n").arg(dir));
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
