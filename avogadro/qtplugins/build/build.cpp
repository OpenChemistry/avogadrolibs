/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Albert DeFusco

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "build.h"
#include "supercelldialog.h"

#include <avogadro/core/unitcell.h>
#include <avogadro/core/crystaltools.h>
#include <avogadro/core/avospglib.h>

#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QInputDialog>

#include <QtWidgets/QAction>
#include <QtWidgets/QMessageBox>

#include <QtCore/QStringList>
#include <QtCore/QDebug>

using Avogadro::Core::CrystalTools;
using Avogadro::Core::AvoSpglib;
using Avogadro::Core::UnitCell;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

Build::Build(QObject *parent_) :
  Avogadro::QtGui::ExtensionPlugin(parent_),
  m_molecule(NULL),
  m_superCellDialog(NULL),
  m_buildSuperCellAction(new QAction(this)),
  m_buildSlabAction(new QAction(this))
{

  m_buildSuperCellAction->setText(tr("Build Super &Cell..."));
  connect(m_buildSuperCellAction, SIGNAL(triggered()), SLOT(buildSuperCell()));
  m_actions.push_back(m_buildSuperCellAction);
  m_buildSuperCellAction->setProperty("menu priority", -1);

  m_buildSlabAction->setText(tr("Build &Slab..."));
  connect(m_buildSlabAction, SIGNAL(triggered()), SLOT(buildSlab()));
  m_actions.push_back(m_buildSlabAction);
  m_buildSlabAction->setProperty("menu priority", -10);

  updateActions();
}

Build::~Build()
{

  qDeleteAll(m_actions);
  m_actions.clear();
}

QList<QAction *> Build::actions() const
{
  return m_actions;
}

QStringList Build::menuPath(QAction *) const
{
  return QStringList() << tr("&Build");
}

void Build::setMolecule(QtGui::Molecule *mol)
{
  if (m_molecule == mol)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = mol;

  if (m_molecule)
    connect(m_molecule, SIGNAL(changed(uint)), SLOT(moleculeChanged(uint)));

  updateActions();
}

void Build::moleculeChanged(unsigned int c)
{
  Q_ASSERT(m_molecule == qobject_cast<Molecule*>(sender()));

  Molecule::MoleculeChanges changes =
      static_cast<Molecule::MoleculeChanges>(c);

  if (changes & Molecule::UnitCell) {
    if (changes & Molecule::Added || changes & Molecule::Removed)
      updateActions();
  }
}

void Build::updateActions()
{
  // Disable everything for NULL molecules.
  if (!m_molecule) {
    foreach (QAction *action, m_actions)
      action->setEnabled(false);
    return;
  }

  if (m_molecule->unitCell()) {
    foreach (QAction *action, m_actions)
      action->setEnabled(true);

  }
  else {
    foreach (QAction *action, m_actions)
      action->setEnabled(false);

  }
}

void Build::buildSuperCell()
{
  if(!m_molecule->unitCell())
    return;
  if (!m_superCellDialog) {
    m_superCellDialog = new SuperCellDialog(qobject_cast<QWidget*>(parent()));
    m_superCellDialog->setMolecule(m_molecule);
  }

  m_superCellDialog->show();
}

void Build::buildSlab()
{
  if(!m_molecule->unitCell())
    return;
}

} // namespace QtPlugins
} // namespace Avogadro
