/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CLIENTSERVER_H
#define AVOGADRO_QTPLUGINS_CLIENTSERVER_H

#include <avogadro/qtgui/extensionplugin.h>

class OpenResponse;

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
 * @brief
 */
class ClientServer : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit ClientServer(QObject *parent_ = 0);
  ~ClientServer();

  QString name() const { return tr("Client server"); }
  QString description() const;
  QList<QAction*> actions() const;
  QStringList menuPath(QAction *) const;

public slots:
  void setMolecule(QtGui::Molecule *mol);
  bool readMolecule(QtGui::Molecule &mol);

signals:
  void connectionError();

private slots:
  void openFile();
  void openSettings();
  void onConnectionError();
  void select();

private:
  ConnectionSettingsDialog *m_dialog;
  QAction *m_openAction;
  QAction *m_settingsAction;
  Core::Molecule *m_molecule;
  vtkSocketController *m_controller;
  vtkSocketCommunicator *m_communicator;
  ProtoCall::Runtime::vtkCommunicatorChannel *m_channel;
  QList<QAction *> m_actions;

  void handleResponse(OpenResponse *response);
  bool connectToServer(const QString &host, int port);
  void disconnect();
  bool isConnected();

};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CLIENTSERVER_H
