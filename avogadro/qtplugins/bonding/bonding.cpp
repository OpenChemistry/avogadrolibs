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

#include <QtCore/QSettings>
#include <QtWidgets/QAction>
#include <QtWidgets/QDialog>

#include <vector>

#include "ui_bondingdialog.h"

namespace Avogadro {
namespace QtPlugins {

using Core::Array;
using Core::Elements;

typedef Avogadro::Core::Array<Avogadro::Core::Bond> NeighborListType;

Bonding::Bonding(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_),
    m_action(new QAction(tr("Bond Atoms"), this)),
    m_clearAction(new QAction(tr("Remove Bonds"), this)),
    m_configAction(new QAction(tr("Configure Bonding…"), this)),
    m_dialog(nullptr), m_ui(nullptr)
{
  QSettings settings;
  m_tolerance = settings.value("bonding/tolerance", 0.45).toDouble();
  m_minDistance = settings.value("bonding/minDistance", 0.32).toDouble();

  m_action->setShortcut(QKeySequence("Ctrl+B"));
  connect(m_action, SIGNAL(triggered()), SLOT(bond()));
  connect(m_clearAction, SIGNAL(triggered()), SLOT(clearBonds()));
  connect(m_configAction, SIGNAL(triggered()), SLOT(configure()));
}

Bonding::~Bonding() {}

QList<QAction*> Bonding::actions() const
{
  QList<QAction*> result;
  return result << m_action << m_clearAction << m_configAction;
}

QStringList Bonding::menuPath(QAction*) const
{
  return QStringList() << tr("&Build") << tr("Bond");
}

void Bonding::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void Bonding::configure()
{
  if (!m_ui) {
    m_dialog = new QDialog(qobject_cast<QWidget*>(parent()));
    m_ui = new Ui::BondingDialog;
    m_ui->setupUi(m_dialog);

    m_ui->toleranceSpinBox->setValue(m_tolerance);
    m_ui->minimumSpinBox->setValue(m_minDistance);

    connect(m_ui->buttonBox, SIGNAL(accepted()), this, SLOT(setValues()));
    connect(m_ui->buttonBox, SIGNAL(rejected()), m_dialog, SLOT(close()));
  }

  m_dialog->show();
  m_dialog->activateWindow();
}

void Bonding::setValues()
{
  if (m_dialog == nullptr || m_ui == nullptr)
    return;
  m_dialog->close();

  m_tolerance = m_ui->toleranceSpinBox->value();
  m_minDistance = m_ui->minimumSpinBox->value();

  QSettings settings;
  settings.setValue("bonding/tolerance", m_tolerance);
  settings.setValue("bonding/minDistance", m_minDistance);
}

void Bonding::bond()
{
  // Yes, this is largely reproduced from Core::Molecule::perceiveBondsSimple
  //  .. but that class doesn't know about selections
  if (!m_molecule)
    return;

  // Check for 3D coordinates, can't do bond perception without this.
  if (m_molecule->atomPositions3d().size() != m_molecule->atomCount())
    return;

  // cache atomic radii
  std::vector<double> radii(m_molecule->atomCount());
  for (size_t i = 0; i < radii.size(); i++) {
    radii[i] = Elements::radiusCovalent(m_molecule->atomicNumbers()[i]);
    if (radii[i] <= 0.0)
      radii[i] = 0.0;
  }

  bool emptySelection = m_molecule->isSelectionEmpty();
  double minSq = m_minDistance * m_minDistance;

  // Main bond perception loop based on a simple distance metric.
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (!emptySelection && !m_molecule->atomSelected(i))
      continue;

    Vector3 ipos = m_molecule->atomPositions3d()[i];
    for (Index j = i + 1; j < m_molecule->atomCount(); ++j) {
      if (!emptySelection && !m_molecule->atomSelected(j))
        continue;

      double cutoff = radii[i] + radii[j] + m_tolerance;
      Vector3 jpos = m_molecule->atomPositions3d()[j];
      Vector3 diff = jpos - ipos;

      if (std::fabs(diff[0]) > cutoff || std::fabs(diff[1]) > cutoff ||
          std::fabs(diff[2]) > cutoff ||
          (m_molecule->atomicNumbers()[i] == 1 &&
           m_molecule->atomicNumbers()[j] == 1)) {
        continue;
      }

      // check radius and add bond if needed
      double cutoffSq = cutoff * cutoff;
      double diffsq = diff.squaredNorm();
      if (diffsq < cutoffSq && diffsq > minSq)
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
                                                     itEnd = bondIndices.rend();
         it != itEnd; ++it) {
      m_molecule->removeBond(*it);
    }
  } // end else(selected atoms)
  m_molecule->emitChanged(QtGui::Molecule::Bonds);
}

} // namespace QtPlugins
} // namespace Avogadro
