/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_DOWNLOADERWIDGET_H
#define AVOGADRO_DOWNLOADERWIDGET_H

#include <QtCore/QList>
#include <QtCore/QStringList>
#include <QtCore/QVariantMap>

#include <QtWidgets/QDialog>

#include <nlohmann/json.hpp>

class QNetworkAccessManager;
class QNetworkReply;

namespace Ui {
class DownloaderWidget;
}

namespace Avogadro {

namespace QtPlugins {

class DownloaderWidget : public QDialog
{
  Q_OBJECT

public:
  DownloaderWidget(QWidget* parent = nullptr);
  ~DownloaderWidget() override;

public slots:
  void showREADME();
  void downloadREADME(int, int);
  void updateRepoData();
  void getCheckedRepos();
  void handleRedirect();
  void unzipPlugin();

private:
  struct repo
  {
    QString name;
    QString description;
    QString releaseVersion;
    QString type;
    QString updatedAt;
    QString zipballUrl;
    QString baseUrl;
    QString readmeUrl;
    bool hasRelease;

    // Default constructor
    repo()
      : name("Error"), description("Error"), releaseVersion("Error"),
        type("other"), updatedAt("Error"), zipballUrl("Error"),
        baseUrl("Error"), readmeUrl("Error"), hasRelease(false)
    {}
  };

  struct downloadEntry
  {
    QString url;
    QString name;
    QString type;
  };

  void downloadNextPlugin();
  // for now, the default path
  void getRepoData(QString url = "https://avogadro.cc/plugins.json");
  void downloadNext();
  bool checkSHA1(QByteArray);

  std::vector<repo> m_repoList;
  Ui::DownloaderWidget* m_ui;
  QNetworkAccessManager* m_NetworkAccessManager;
  QNetworkReply* m_reply;
  /** Holds a node of JSON results */
  nlohmann::json m_root;
  /** Used to parse JSON results */
  QVariantMap m_jsonResult;

  QString m_filePath;

  QList<downloadEntry> m_downloadList;
};
} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_DOWNLOADERWIDGET_H
