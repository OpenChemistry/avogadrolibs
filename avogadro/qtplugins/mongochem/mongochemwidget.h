/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_MONGOCHEMWIDGET_H
#define AVOGADRO_QTPLUGINS_MONGOCHEMWIDGET_H

#include <QScopedPointer>
#include <QSharedPointer>
#include <QWidget>

namespace Ui {
class MongoChemWidget;
}

class QNetworkAccessManager;
class QNetworkReply;

namespace Avogadro {

namespace QtPlugins {

class ConfigDialog;
class ListMoleculesModel;
class MongoChem;
class SubmitCalculationDialog;

class MongoChemWidget : public QWidget
{
  Q_OBJECT

public:
  explicit MongoChemWidget(MongoChem* plugin, QWidget* parent = nullptr);
  ~MongoChemWidget() override;

private slots:
  void showConfig();
  void finishAuthentication(const QVariant& results);
  void search();
  void finishSearch(const QVariant& results);
  void downloadSelectedMolecule();
  void finishDownloadMolecule(const QVariant& results);
  void uploadMolecule();
  void finishUploadMolecule(const QVariant& results);
  void uploadGeometry(const QString& moleculeId);
  void finishUploadGeometry(const QVariant& results);
  void submitCalculation();
  void finishSubmitCalculation(const QVariantMap& results);
  void finishWatchCalculation(const QByteArray& cjson);
  void error(const QString& message, QNetworkReply* reply = nullptr);

  void readSettings();
  void writeSettings();

private:
  void setupConnections();
  void authenticate();
  int selectedRow();

  MongoChem* m_plugin;

  QString m_girderUrl = "http://localhost:8080/api/v1";
  QString m_apiKey;
  QString m_girderToken;

  QScopedPointer<Ui::MongoChemWidget> m_ui;
  QSharedPointer<QNetworkAccessManager> m_networkManager;
  QScopedPointer<ConfigDialog> m_configDialog;
  QScopedPointer<ListMoleculesModel> m_listMoleculesModel;
  QScopedPointer<SubmitCalculationDialog> m_submitCalculationDialog;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MONGOCHEMWIDGET_H
