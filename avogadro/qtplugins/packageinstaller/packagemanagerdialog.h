/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PACKAGEMANAGERDIALOG_H
#define AVOGADRO_QTPLUGINS_PACKAGEMANAGERDIALOG_H

#include <QtCore/QList>
#include <QtCore/QModelIndex>
#include <QtCore/QString>
#include <QtWidgets/QDialog>

class QNetworkAccessManager;
class QNetworkReply;
class QSortFilterProxyModel;

namespace Ui {
class PackageManagerDialog;
}

namespace Avogadro {
namespace QtPlugins {

class PackageModel;

/**
 * @brief Dialog for browsing, installing, updating, and removing Avogadro
 * packages. Replaces the old DownloaderWidget.
 *
 * Combines the online catalog from avogadro.cc/plugins.json with locally
 * installed packages tracked by PackageManager.
 */
class PackageManagerDialog : public QDialog
{
  Q_OBJECT

public:
  explicit PackageManagerDialog(QWidget* parent = nullptr);
  ~PackageManagerDialog() override;

private slots:
  void refreshOnlineCatalog();
  void onCatalogReply();
  void onReadmeReply();
  void onTableClicked(const QModelIndex& index);
  void installSelected();
  void removeSelected();
  void installFromDirectory();
  void onPackagesInstalled();
  void handleRedirect();

private:
  void getRepoData(
    const QString& url = QStringLiteral("https://avogadro.cc/plugins.json"));
  void downloadNext();
  void unzipPlugin(QNetworkReply* reply);
  static bool copyDir(const QString& src, const QString& dst);

  struct DownloadEntry
  {
    QString url;
    QString name;
  };

  Ui::PackageManagerDialog* m_ui = nullptr;
  PackageModel* m_model = nullptr;
  QSortFilterProxyModel* m_proxyModel = nullptr;
  QNetworkAccessManager* m_network = nullptr;
  QString m_filePath;
  QList<DownloadEntry> m_downloadQueue;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_PACKAGEMANAGERDIALOG_H
