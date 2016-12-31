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

#include "mongochem.h"

#include <QtWidgets/QAction>
#include <QtCore/QDebug>
#include <QtCore/QStringList>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/io/fileformatmanager.h>
#include <molequeue/client/jsonrpcclient.h>

namespace Avogadro {
namespace QtPlugins {

MongoChem::MongoChem(QObject *parent_) :
  Avogadro::QtGui::ExtensionPlugin(parent_),
  m_action(new QAction(this)),
  m_molecule(nullptr)
{
  m_action->setEnabled(true);
  m_action->setText("&Show Similar Molecules in MongoChem...");
  connect(m_action, SIGNAL(triggered()), SLOT(showSimilarMolecules()));
}

MongoChem::~MongoChem()
{
}

QString MongoChem::description() const
{
  return tr("View general properties of a molecule.");
}

QList<QAction *> MongoChem::actions() const
{
  return QList<QAction*>() << m_action;
}

void MongoChem::setMolecule(QtGui::Molecule *mol)
{
  if (mol == m_molecule)
    return;

  m_molecule = mol;
}

QStringList MongoChem::menuPath(QAction *) const
{
  return QStringList() << tr("&Extensions");
}

void MongoChem::showSimilarMolecules()
{
  if (!m_molecule)
    return;

  // get inchi for molecule
  std::string inchi;
  Io::FileFormatManager &ffm = Io::FileFormatManager::instance();
  if (!ffm.writeString(*m_molecule, inchi, "inchi")){
    qDebug() << "error converting molecule to inchi.";
    return;
  }

  // connect to mongochem
  MoleQueue::JsonRpcClient *client = new MoleQueue::JsonRpcClient(this);
  if (!client->connectToServer("mongochem")) {
      qDebug() << "failed to connect to mongochem";
      return;
  }

  // send request
  QJsonObject request(client->emptyRequest());
  request["method"] = QLatin1String("findSimilarMolecules");

  QJsonObject params;
  params["identifier"] = QLatin1String(inchi.c_str());
  params["inputFormat"] = QLatin1String("inchi");
  request["params"] = params;
  client->sendRequest(request);
}

} // namespace QtPlugins
} // namespace Avogadro
