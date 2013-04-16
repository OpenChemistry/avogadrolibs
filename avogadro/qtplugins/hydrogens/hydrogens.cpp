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

#include "hydrogens.h"

#include <avogadro/core/hydrogentools.h>
#include <avogadro/qtgui/molecule.h>

#include <QtGui/QAction>
#include <QtGui/QKeySequence>

#include <QtCore/QStringList>

namespace Avogadro {
namespace QtPlugins {

Hydrogens::Hydrogens(QObject *parent_) :
  Avogadro::QtGui::ExtensionPlugin(parent_),
  m_molecule(NULL)
{
  QAction *action = new QAction(tr("Adjust &Hydrogens (Add and Remove)"), this);
  action->setShortcut(QKeySequence("Ctrl+Alt+H"));
  connect(action, SIGNAL(triggered()), SLOT(adjustHydrogens()));
  m_actions.append(action);

  action = new QAction(tr("Adjust Hydrogens (&Add Only)"), this);
  connect(action, SIGNAL(triggered()), SLOT(addHydrogens()));
  m_actions.append(action);

  action = new QAction(tr("Adjust Hydrogens (&Remove Only)"), this);
  connect(action, SIGNAL(triggered()), SLOT(removeHydrogens()));
  m_actions.append(action);

  action = new QAction(tr("&Remove All Hydrogens"), this);
  connect(action, SIGNAL(triggered()), SLOT(removeAllHydrogens()));
  m_actions.append(action);
}

Hydrogens::~Hydrogens()
{
}

QString Hydrogens::description() const
{
  return tr("Add/remove hydrogens from the current molecule.");
}

QList<QAction *> Hydrogens::actions() const
{
  return m_actions;
}

QStringList Hydrogens::menuPath(QAction *) const
{
  return QStringList() << tr("&Edit");
}

void Hydrogens::setMolecule(QtGui::Molecule *mol)
{
  m_molecule = mol;
}

void Hydrogens::adjustHydrogens()
{
  if (m_molecule) {
    Core::HydrogenTools::adjustHydrogens(*m_molecule,
                                         Core::HydrogenTools::AddAndRemove);
    // Assume molecule changes...
    m_molecule->emitChanged(QtGui::Molecule::Atoms
                            | QtGui::Molecule::Bonds
                            | QtGui::Molecule::Added
                            | QtGui::Molecule::Removed);
  }
}

void Hydrogens::addHydrogens()
{
  if (m_molecule) {
    Core::HydrogenTools::adjustHydrogens(*m_molecule, Core::HydrogenTools::Add);
    // Assume molecule changes...
    m_molecule->emitChanged(QtGui::Molecule::Atoms
                            | QtGui::Molecule::Bonds
                            | QtGui::Molecule::Added);
  }
}

void Hydrogens::removeHydrogens()
{
  if (m_molecule) {
    Core::HydrogenTools::adjustHydrogens(*m_molecule,
                                         Core::HydrogenTools::Remove);
    // Assume molecule changes...
    m_molecule->emitChanged(QtGui::Molecule::Atoms
                            | QtGui::Molecule::Bonds
                            | QtGui::Molecule::Removed);
  }
}

void Hydrogens::removeAllHydrogens()
{
  if (m_molecule) {
    Core::HydrogenTools::removeAllHydrogens(*m_molecule);
    // Assume molecule changes...
    m_molecule->emitChanged(QtGui::Molecule::Atoms
                            | QtGui::Molecule::Bonds
                            | QtGui::Molecule::Removed);
  }
}

} // namespace QtPlugins
} // namespace Avogadro
