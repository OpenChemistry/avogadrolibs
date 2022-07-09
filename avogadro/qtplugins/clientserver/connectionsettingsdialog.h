/******************************************************************************
 This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
 ******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CONNECTIONSETTINGSDIALOG_H
#define AVOGADRO_QTPLUGINS_CONNECTIONSETTINGSDIALOG_H

#include <QtGui/QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class ConnectionSettingsDialog;
}

/**
 * @class ConnectionSettingsDialog connectionsettingsdialog.h
 * <avogadro/qtplugins/clientserver/connectionsettingsdialog.h>
 * @brief Dialog to set the connection settings for connecting to a remote
 * server.
 */
class ConnectionSettingsDialog : public QDialog
{
  Q_OBJECT
public:
  explicit ConnectionSettingsDialog(QWidget* parent_ = nullptr);
  virtual ~ConnectionSettingsDialog();

  static const QString defaultHost;
  static const int defaultPort = 6060;

signals:
  void settingsChanged();

private slots:
  void testConnection();
  void updateSettings();

private:
  Ui::ConnectionSettingsDialog* m_ui;
};

} /* namespace QtPlugins */
} /* namespace Avogadro */

#endif /* AVOGADRO_QTPLUGINS_CONNECTIONSETTINGSDIALOG_H */
