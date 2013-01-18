/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "gamessinput.h"

#include "gamessinputdialog.h"

#include <QtCore/QtPlugin>
#include <QtCore/QStringList>

#include <QtGui/QAction>
#include <QtGui/QDialog>

#include <QtCore/QDebug>

namespace Avogadro {
namespace Core {
class Molecule;
}
namespace QtPlugins {

GamessInput::GamessInput(QObject *parent_) :
  ExtensionPlugin(parent_),
  m_action(new QAction(this)),
  m_molecule(NULL),
  m_dialog(NULL)
{
  m_action->setEnabled(true);
  m_action->setText(tr("&GAMESS"));
  connect(m_action, SIGNAL(triggered()), SLOT(menuActivated()));
}

GamessInput::~GamessInput()
{
  if (m_dialog)
    m_dialog->deleteLater();
}

QList<QAction *> GamessInput::actions() const
{
  QList<QAction *> actions_;
  actions_.append(m_action);
  return actions_;
}

QStringList GamessInput::menuPath(QAction *) const
{
  QStringList path;
  path << tr("&Extensions") << tr("&Input Generators");
  return path;
}

void GamessInput::setMolecule(QtGui::Molecule *mol)
{
  if (m_dialog)
    m_dialog->setMolecule(mol);
  m_molecule = mol;
}

void GamessInput::menuActivated()
{
  if (!m_dialog)
    m_dialog = new GamessInputDialog;
  m_dialog->setMolecule(m_molecule);
  m_dialog->show();
}

}
}
