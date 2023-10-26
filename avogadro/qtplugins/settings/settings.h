/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SETTINGS_H
#define AVOGADRO_QTPLUGINS_SETTINGS_H

#include <QApplication>
#include <QVBoxLayout>
#include <QCheckBox>
#include <QProcess>
#include <QMessageBox>
#include <QStringList>
#include <QString>
#include <QSysInfo>
#include <QtCore/QList>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QAction>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

#include <avogadro/qtgui/extensionplugin.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QString>

class QNetworkAccessManager;
class QNetworkReply;
class QProgressDialog;

namespace Avogadro {
namespace QtPlugins {

class Settings;

/**
 * @brief Downloads Github repos and extracts their contents into a Avogadro
 * folder for plugins, molecule data, etc..
 */

class Settings : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit Settings(QObject* parent = nullptr);
  ~Settings() override;

  QString name() const override { return tr("Settings"); }

  QString description() const override
  {
    return tr("General settings on avogadro");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule*) override;
  bool readMolecule(QtGui::Molecule&) override;

private slots:
  void showDialog();

private:
  QAction* m_action;
  QWidget* m_window;
  QNetworkAccessManager* m_network;
  QStringList detectPythonInterpreters();
  void activateEnvironment(const QString& envType, const QString& envName);
};
}
}

#endif
