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

#include "clientserver.h"
#include "RemoteMoleculeService.pb.h"
#include "connectionsettingsdialog.h"
#include "filedialog.h"

#include <QtGui/QAction>
#include <QtGui/QMessageBox>
#include <QtCore/QDebug>
#include <QtCore/QStringList>
#include <QtGui/QFileDialog>
#include <QtCore/QFileInfo>
#include <QtCore/QSettings>
#include <QtCore/QTimer>

#include <vtkNew.h>
#include <vtkSocketController.h>
#include <vtkSocketCommunicator.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/io/fileformatmanager.h>

#include <protocall/runtime/vtkcommunicatorchannel.h>
#include <google/protobuf/stubs/common.h>

using namespace google::protobuf;
using namespace ProtoCall::Runtime;

namespace Avogadro {
namespace QtPlugins {

ClientServer::ClientServer(QObject *parent_) :
  Avogadro::QtGui::ExtensionPlugin(parent_),
  m_openAction(new QAction(this)), m_settingsAction(new QAction(this)),
  m_molecule(NULL), m_controller(NULL), m_communicator(NULL), m_channel(NULL)
{
  m_openAction->setEnabled(true);
  m_openAction->setText("Open Molecule");
  m_actions.append(m_openAction);

  m_settingsAction->setEnabled(true);
  m_settingsAction->setText("Settings");
  m_actions.append(m_settingsAction);

  connect(m_openAction, SIGNAL(triggered()), SLOT(openFile()));
  connect(m_settingsAction, SIGNAL(triggered()), SLOT(openSettings()));
  connect(this, SIGNAL(connectionError()), SLOT(onConnectionError()));
}

ClientServer::~ClientServer()
{
  disconnect();
}

QString ClientServer::description() const
{
  return tr("Client server operations.");
}

QList<QAction *> ClientServer::actions() const
{
  return m_actions;
}

QStringList ClientServer::menuPath(QAction *) const
{
  return QStringList() << tr("&Extensions") << tr("S&erver");
}

void ClientServer::disconnect() {

  if (m_communicator)
    m_communicator->CloseConnection();

  delete m_channel;
  m_channel = NULL;
  if (m_communicator)
    m_communicator->Delete();
  if (m_controller)
    m_controller->Delete();
}

void ClientServer::select() {
  if (m_channel) {
    if (m_channel->select()) {
      if (!m_channel->receive()) {
        emit connectionError();
        return;
      }
    }
    QTimer::singleShot(100, this, SLOT(select()));
  }
}

bool ClientServer::isConnected()
{
  return m_channel != NULL;
}

bool ClientServer::connectToServer(const QString &host, int port) {

  if (m_channel)
    disconnect();

  m_controller = vtkSocketController::New();
  m_communicator = vtkSocketCommunicator::New();
  m_controller->SetCommunicator(m_communicator);
  m_controller->Initialize();

  if (!m_communicator->ConnectTo(host.toLocal8Bit().data(), port)) {
    m_controller->Delete();
    m_communicator->Delete();

    return false;
  }

  m_channel = new vtkCommunicatorChannel(m_communicator);

  // Start the event loop
  select();

  return true;
}

void ClientServer::openFile()
{
  QSettings settings;
  if (!isConnected()) {
    QString host = settings
                     .value("clientServer/connectionSettings/hostName")
                       .toString();
    int port = settings.value("clientServer/connectionSettings/port").toInt();

    if (!connectToServer(host.toLocal8Bit().data(), port)) {
      QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                            tr("Connection failed"),
                            tr("The connection to %2:%3 failed: connection"
                               " refused.").arg(host).arg(port));
      return;
    }
  }

  RemoteMoleculeService::Proxy proxy(m_channel);
  FileFormats *response = new FileFormats();
  Closure *callback = NewCallback(this,
                        &ClientServer::handleFileFormatsResponse, response);

  proxy.fileFormats(response, callback);
}

void ClientServer::openFile(const QString &filePath)
{
  QSettings settings;
  QFileInfo fileInfo(filePath);
  settings.setValue(lastOpenDirSettingPath(), fileInfo.dir().path());

  RemoteMoleculeService::Proxy proxy(m_channel);

  OpenRequest request;
  request.set_path(filePath.toStdString());

  OpenResponse *response = new OpenResponse();
  Closure *callback = NewCallback(this, &ClientServer::handleOpenResponse,
     response);

 proxy.open(&request, response, callback);
}

void ClientServer::setMolecule(QtGui::Molecule *mol)
{
  // Do nothing
}

bool ClientServer::readMolecule(QtGui::Molecule &mol) {
  if (m_molecule) {
    mol = *m_molecule;

    return true;
  }

  return false;
}

void ClientServer::handleOpenResponse(OpenResponse *response)
{
  if (!response->hasError()) {
    m_molecule = response->mutable_molecule()->get();

    emit ExtensionPlugin::moleculeReady(1);
  }
  else {
    QMessageBox::warning(qobject_cast<QWidget*>(parent()),
                           tr("Remote service error"),
                           response->errorString().c_str());
    return;
  }

  delete response;
}

void ClientServer::onConnectionError()
{
  QMessageBox::critical(qobject_cast<QWidget*>(parent()),
                        tr("Remote service error"),
                        tr("Connection failed with: %1").arg(
                        m_channel->errorString().c_str()));
  disconnect();
}

void ClientServer::openSettings()
{
  if (!m_dialog)
    m_dialog = new ConnectionSettingsDialog(qobject_cast<QWidget*>(parent()));

  m_dialog->show();
}


QString ClientServer::lastOpenDirSettingPath()
{
  QSettings settings;
  QString host = settings.value("clientServer/connectionSettings/hostName")
                      .toString();
  QString port = settings.value("clientServer/connectionSettings/port")
                      .toString();

  QString settingsPath = tr("clientServer/%1:%2/lastOpenDir")
                          .arg(host).arg(port);

  return settingsPath;
}

void ClientServer::handleFileFormatsResponse(FileFormats *response)
{
  QSettings settings;

  QStringList filters;
  for (int i=0; i<response->formats_size(); i++)
  {
    FileFormat format = response->formats(i);
    QString filter = tr("%1 (").arg(QString::fromStdString(format.name()));
    for (int j=0; j<format.extension_size(); j++)
    {
      filter += tr("*.%1").arg(QString::fromStdString(format.extension(j)));

      if (j != format.extension_size()-1)
        filter += " ";
    }

    filter += ")";
    filters << filter;
  }

  qDebug() << filters.join(";;");

  QString dir = settings.value(lastOpenDirSettingPath()).toString();
  FileDialog *remoteFileDialog = new FileDialog(m_channel, NULL,
      QString("Remote File Dialog"), dir, filters.join(";;"));

  connect(remoteFileDialog, SIGNAL(accepted()), this, SLOT(onAccepted()));
  connect(remoteFileDialog, SIGNAL(finished(int)), this, SLOT(onFinished(int)));

  remoteFileDialog->show();

  delete response;
}

void ClientServer::onAccepted()
{
  FileDialog *dialog = qobject_cast<FileDialog*>(sender());

  if (!dialog)
    return;

  QString file = dialog->getSelectedFile();

  if (!file.isEmpty())
    openFile(file);
}

void ClientServer::onFinished(int result)
{
  FileDialog *dialog = qobject_cast<FileDialog*>(sender());

  if (dialog)
    dialog->deleteLater();
}

} // namespace QtPlugins
}
