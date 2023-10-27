/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_PluginManagerWidget_H
#define AVOGADRO_PluginManagerWidget_H

#include <QtCore/QList>
#include <QtCore/QStringList>
#include <QtCore/QVariantMap>
#include <QtCore/QSettings>
#include <QtWidgets/QDialog>

#include <nlohmann/json.hpp>

class QNetworkAccessManager;
class QNetworkReply;

namespace Ui {
class PluginManagerWidget;
}

namespace Avogadro {

namespace QtPlugins {

class PluginManagerWidget : public QDialog
{
  Q_OBJECT

public:
  PluginManagerWidget(QWidget* parent = nullptr);
  ~PluginManagerWidget() override;
  QSettings m_settings;

public slots:
  void showDownloadedPluginDescription();
  void downloadPluginDescriptionFor(int, int);
  void updatePluginsList();
  void installCheckedPlugins();
  void installNextPluginFinished();
  void unzipPlugin();
  void installDownloadedPlugin();
  void onInstallMethodChanged(const QString &text);
  void onSetPythonPathClicked();
  void onEnvironmentChanged(const QString &text);
  QString installMethodCodeFromDisplayed(const QString &text);
  QString installMethodDisplayedFromCode(const QString &code);
  void onInstallMethodChangedFromCode(const QString &code);
  void selectInstallerFromCode(const QString &code);
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

  /**
   * Fetch plugins information listed in the given file at the given url  
   * for now, the default path
   */
  void fetchPluginsList(QString url = "https://avogadro.cc/plugins.json");
  void installNextPlugin();
  bool checkSHA1(QByteArray);

  std::vector<repo> m_repoList;
  Ui::PluginManagerWidget* m_ui;
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
#endif // AVOGADRO_PluginManagerWidget_H
