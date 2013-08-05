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

#include "connectionsettingsdialog.h"
#include "ui_connectionsettingsdialog.h"

#include <vtkNew.h>
#include <vtkSocketController.h>
#include <vtkSocketCommunicator.h>

#include <QtGui/QMessageBox>
#include <QtCore/QSettings>
#include <QtCore/QVariant>

namespace Avogadro
{
namespace QtPlugins
{

ConnectionSettingsDialog::ConnectionSettingsDialog(QWidget *parent_) :
  QDialog(parent_), m_ui(new Ui::ConnectionSettingsDialog)
{
  m_ui->setupUi(this);

  connect(m_ui->pushTestConnection, SIGNAL(clicked()), SLOT(testConnection()));
  connect(m_ui->buttonBox, SIGNAL(accepted()), SLOT(updateSettings()));

  QSettings settings;
  QString host = settings.value("clientServer/connectionSettings/hostName")
                      .toString();
  int port = settings.value("clientServer/connectionSettings/port").toInt();

  m_ui->editHostName->setText(host);
  m_ui->spinPort->setValue(port);
}

ConnectionSettingsDialog::~ConnectionSettingsDialog()
{

}

void ConnectionSettingsDialog::testConnection()
{
  QString host = m_ui->editHostName->text();
  int port = m_ui->spinPort->value();

  vtkNew<vtkSocketController> controller;
  vtkNew<vtkSocketCommunicator> communicator;
  controller->SetCommunicator(communicator.GetPointer());
  controller->Initialize();

  if (!communicator->ConnectTo(host.toLocal8Bit().data(), port)) {
    QMessageBox::critical(this, tr("Connection refused"),
                        tr("The connection to %2:%3 failed: connection"
                           " refused.").arg(host).arg(port));

  }
  else {
    QMessageBox::information(this, tr("Success"),
                             tr("Connection to %2:%3 succeeded!")
                             .arg(host).arg(port));

    communicator->CloseConnection();
  }
}

void ConnectionSettingsDialog::updateSettings()
{
  QSettings settings;
  QVariant host(m_ui->editHostName->text());
  QVariant port(m_ui->spinPort->value());

  settings.setValue("clientServer/connectionSettings/hostName", host);
  settings.setValue("clientServer/connectionSettings/port", port);
}

} /* namespace QtPlugins */
} /* namespace Avogadro */
