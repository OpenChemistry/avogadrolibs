/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2009 Marcus D. Hanwell
  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "networkdatabases.h"

#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>

#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtWidgets/QAction>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

namespace Avogadro {
namespace QtPlugins {

NetworkDatabases::NetworkDatabases(QObject* parent_)
  : ExtensionPlugin(parent_), m_action(new QAction(this)), m_molecule(nullptr),
    m_network(nullptr), m_progressDialog(nullptr)
{
  m_action->setEnabled(true);
  m_action->setText("Download by &Name...");
  connect(m_action, SIGNAL(triggered()), SLOT(showDialog()));
}

NetworkDatabases::~NetworkDatabases()
{
}

QList<QAction*> NetworkDatabases::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList NetworkDatabases::menuPath(QAction*) const
{
  return QStringList() << tr("&File") << tr("&Import");
}

void NetworkDatabases::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

bool NetworkDatabases::readMolecule(QtGui::Molecule& mol)
{
  if (m_moleculeData.isEmpty() || m_moleculeName.isEmpty())
    return false;

  bool readOK = Io::FileFormatManager::instance().readString(
    mol, m_moleculeData.data(), "sdf");
  if (readOK) // worked, so set the filename
    mol.setData("name", m_moleculeName.toStdString());

  return readOK;
}

void NetworkDatabases::showDialog()
{
  if (!m_network) {
    m_network = new QNetworkAccessManager(this);
    connect(m_network, SIGNAL(finished(QNetworkReply*)), this,
            SLOT(replyFinished(QNetworkReply*)));
  }
  if (!m_progressDialog) {
    m_progressDialog = new QProgressDialog(qobject_cast<QWidget*>(parent()));
  }
  // Prompt for a chemical structure name
  bool ok;
  QString structureName = QInputDialog::getText(
    qobject_cast<QWidget*>(parent()), tr("Chemical Name"),
    tr("Chemical structure to download."), QLineEdit::Normal, "", &ok);

  if (!ok || structureName.isEmpty())
    return;

  // Hard coding the NIH resolver download URL - this could be used for other
  // services
  m_network->get(QNetworkRequest(
    QUrl("https://cactus.nci.nih.gov/chemical/structure/" + structureName +
         "/sdf?get3d=true" +
         "&resolver=name_by_opsin,name_by_cir,name_by_chemspider" +
         "&requester=Avogadro2")));

  m_moleculeName = structureName;
  m_progressDialog->setLabelText(tr("Querying for %1").arg(structureName));
  m_progressDialog->setRange(0, 0);
  m_progressDialog->show();
}

void NetworkDatabases::replyFinished(QNetworkReply* reply)
{
  m_progressDialog->hide();
  // Read in all the data
  if (!reply->isReadable()) {
    QMessageBox::warning(qobject_cast<QWidget*>(parent()),
                         tr("Network Download Failed"),
                         tr("Network timeout or other error."));
    reply->deleteLater();
    return;
  }

  m_moleculeData = reply->readAll();
  // Check if the file was successfully downloaded
  if (m_moleculeData.contains("Error report") ||
      m_moleculeData.contains("Page not found (404)")) {
    QMessageBox::warning(
      qobject_cast<QWidget*>(parent()), tr("Network Download Failed"),
      tr("Specified molecule could not be found: %1").arg(m_moleculeName));
    reply->deleteLater();
    return;
  }
  emit moleculeReady(1);
  reply->deleteLater();
}
}
}
