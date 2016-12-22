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

#include "bonding.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtGui/QClipboard>
#include <QtGui/QIcon>
#include <QtGui/QKeySequence>
#include <QtWidgets/QMessageBox>

#include <string>
#include <vector>

namespace Avogadro {
namespace QtPlugins {

using Core::Elements;
using Core::Array;

typedef Avogadro::Core::Array<Avogadro::Core::Bond> NeighborListType;

Bonding::Bonding(QObject *parent_) :
  Avogadro::QtGui::ExtensionPlugin(parent_),
  m_action(new QAction(tr("Bond Atoms"), this)),
  m_clearAction(new QAction(tr("Remove Bonds"), this))
{
  m_action->setShortcut(QKeySequence("Ctrl+B"));
  connect(m_action, SIGNAL(triggered()), SLOT(bond2()));
  connect(m_clearAction, SIGNAL(triggered()), SLOT(clearBonds()));
}

Bonding::~Bonding()
{
}

QList<QAction *> Bonding::actions() const
{
  QList<QAction *> result;
  return result << m_action << m_clearAction;
}

QStringList Bonding::menuPath(QAction *) const
{
  return QStringList() << tr("&Build");
}

void Bonding::setMolecule(QtGui::Molecule *mol)
{
  m_molecule = mol;
}

void Bonding::bond()
{
  if (!m_molecule)
    return;

  m_molecule->perceiveBondsSimple();
  m_molecule->emitChanged(QtGui::Molecule::Bonds);
}

void Bonding::bond2()
{
  if (!m_molecule)
    return;

  // Check for 3D coordinates, can't do bond perception without this.
  if (m_molecule->atomPositions3d().size() != m_molecule->atomCount())
    return;

  // The tolerance used in position comparisons.
  double tolerance = 0.45;

  // cache atomic radii
  std::vector<double> radii(m_molecule->atomCount());
  for (size_t i = 0; i < radii.size(); i++) {
    radii[i] = Elements::radiusCovalent(m_molecule->atomicNumbers()[i]);
    if (radii[i] <= 0.0)
      radii[i] = 0.0;
  }

  bool emptySelection = m_molecule->isSelectionEmpty();

  // Main bond perception loop based on a simple distance metric.
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (!emptySelection && !m_molecule->atomSelected(i))
      continue;

    Vector3 ipos = m_molecule->atomPositions3d()[i];
    for (Index j = i + 1; j < m_molecule->atomCount(); ++j) {
      if (!emptySelection && !m_molecule->atomSelected(j))
        continue;

      double cutoff = radii[i] + radii[j] + tolerance;
      Vector3 jpos = m_molecule->atomPositions3d()[j];
      Vector3 diff = jpos - ipos;

      if (std::fabs(diff[0]) > cutoff
          || std::fabs(diff[1]) > cutoff
          || std::fabs(diff[2]) > cutoff
          || (m_molecule->atomicNumbers()[i] == 1
              && m_molecule->atomicNumbers()[j] == 1)) {
        continue;
      }

      // check radius and add bond if needed
      double cutoffSq = cutoff * cutoff;
      double diffsq = diff.squaredNorm();
      if (diffsq < cutoffSq && diffsq > 0.1)
        m_molecule->addBond(m_molecule->atom(i), m_molecule->atom(j), 1);
    }
  }
  m_molecule->emitChanged(QtGui::Molecule::Bonds);
}

void Bonding::clearBonds()
{
  // remove any bonds connected to the selected atoms
  //  Array<BondType> bonds(Index a);
  if (m_molecule->isSelectionEmpty())
    m_molecule->clearBonds();
  else {
    std::vector<size_t> bondIndices;
    for (Index i = 0; i < m_molecule->atomCount(); ++i) {
      if (!m_molecule->atomSelected(i))
        continue;

      // OK, the atom is selected, get the bonds to delete
      const NeighborListType bonds = m_molecule->bonds(i);
      for (NeighborListType::const_iterator it = bonds.begin();
           it != bonds.end(); ++it) {
             bondIndices.push_back(it->index());
      }
    } // end looping through atoms

    // now delete the bonds
    for (std::vector<size_t>::const_reverse_iterator it = bondIndices.rbegin(),
         itEnd = bondIndices.rend(); it != itEnd; ++it) {
      m_molecule->removeBond(*it);
    }
  } // end else(selected atoms)
  m_molecule->emitChanged(QtGui::Molecule::Bonds);
}

} // namespace QtPlugins
} // namespace Avogadro
