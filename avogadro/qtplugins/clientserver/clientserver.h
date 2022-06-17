/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CLIENTSERVER_H
#define AVOGADRO_QTPLUGINS_CLIENTSERVER_H

#include <avogadro/qtgui/extensionplugin.h>

class OpenResponse;
class FileFormats;

namespace ProtoCall {
namespace Runtime {
class vtkCommunicatorChannel;
}
}

class vtkSocketController;
class vtkSocketCommunicator;

namespace Avogadro {
namespace Core {
class Molecule;
}

namespace QtPlugins {

class ConnectionSettingsDialog;

/**
 * @class ClientServer clientserver.h
 * <avogadro/qtplugins/clientserver/clientserver.h>
 * @brief Plugin used to connect to and perform remote operations on an
 * Avodadro server.
 */
class ClientServer : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit ClientServer(QObject* parent_ = nullptr);
  ~ClientServer();

  QString name() const { return tr("Client server"); }
  QString description() const;
  QList<QAction*> actions() const;
  QStringList menuPath(QAction*) const;

public slots:
  void setMolecule(QtGui::Molecule* mol);
  bool readMolecule(QtGui::Molecule& mol);

signals:
  void connectionError();

private slots:
  void openFile();
  void openFile(const QString& filePath);
  void openSettings();
  void onConnectionError();
  void select();
  void onAccepted();
  void onFinished(int result);
  void disconnect();

private:
  ConnectionSettingsDialog* m_dialog;
  QAction* m_openAction;
  QAction* m_settingsAction;
  Core::Molecule* m_molecule;
  vtkSocketController* m_controller;
  vtkSocketCommunicator* m_communicator;
  ProtoCall::Runtime::vtkCommunicatorChannel* m_channel;
  QList<QAction*> m_actions;

  void handleOpenResponse(OpenResponse* response);
  void handleFileFormatsResponse(FileFormats* response);
  bool connectToServer(const QString& host, int port);

  bool isConnected();
  QString lastOpenDirSettingPath();
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CLIENTSERVER_H
