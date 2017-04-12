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

#include "crystal.h"

#include "importcrystaldialog.h"
#include "supercelldialog.h"
#include "unitcelldialog.h"
#include "volumescalingdialog.h"

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/unitcell.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtWidgets/QAction>
#include <QtWidgets/QMessageBox>

#include <QtCore/QStringList>

using Avogadro::Core::CrystalTools;
using Avogadro::Core::UnitCell;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

Crystal::Crystal(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr),
    m_unitCellDialog(nullptr),
    m_importCrystalClipboardAction(new QAction(this)),
    m_editUnitCellAction(new QAction(this)),
    m_buildSupercellAction(new QAction(this)),
    m_niggliReduceAction(new QAction(this)),
    m_scaleVolumeAction(new QAction(this)),
    m_standardOrientationAction(new QAction(this)),
    m_toggleUnitCellAction(new QAction(this)),
    m_wrapAtomsToCellAction(new QAction(this))
{
  m_importCrystalClipboardAction->setText(tr("Import Crystal from Clipboard"));
  connect(m_importCrystalClipboardAction, SIGNAL(triggered()),
          SLOT(importCrystalClipboard()));
  m_actions.push_back(m_importCrystalClipboardAction);
  m_importCrystalClipboardAction->setProperty("menu priority", 220);

  // this will be changed when the molecule is set:
  m_toggleUnitCellAction->setText(tr("Toggle Unit Cell"));
  connect(m_toggleUnitCellAction, SIGNAL(triggered()), SLOT(toggleUnitCell()));
  m_actions.push_back(m_toggleUnitCellAction);
  m_toggleUnitCellAction->setProperty("menu priority", 210);

  m_editUnitCellAction->setText(tr("Edit Unit Cell..."));
  connect(m_editUnitCellAction, SIGNAL(triggered()), SLOT(editUnitCell()));
  m_actions.push_back(m_editUnitCellAction);
  m_editUnitCellAction->setProperty("menu priority", 190);

  m_wrapAtomsToCellAction->setText(tr("&Wrap Atoms to Unit Cell"));
  connect(m_wrapAtomsToCellAction, SIGNAL(triggered()),
          SLOT(wrapAtomsToCell()));
  m_actions.push_back(m_wrapAtomsToCellAction);
  m_wrapAtomsToCellAction->setProperty("menu priority", 180);

  m_standardOrientationAction->setText(tr("Rotate to Standard &Orientation"));
  connect(m_standardOrientationAction, SIGNAL(triggered()),
          SLOT(standardOrientation()));
  m_actions.push_back(m_standardOrientationAction);
  m_standardOrientationAction->setProperty("menu priority", 170);

  m_scaleVolumeAction->setText(tr("Scale Cell &Volume"));
  connect(m_scaleVolumeAction, SIGNAL(triggered()), SLOT(scaleVolume()));
  m_actions.push_back(m_scaleVolumeAction);
  m_scaleVolumeAction->setProperty("menu priority", 160);

  m_buildSupercellAction->setText(tr("Build &Supercell"));
  connect(m_buildSupercellAction, SIGNAL(triggered()), SLOT(buildSupercell()));
  m_actions.push_back(m_buildSupercellAction);
  m_buildSupercellAction->setProperty("menu priority", 150);

  m_niggliReduceAction->setText(tr("Reduce Cell (&Niggli)"));
  connect(m_niggliReduceAction, SIGNAL(triggered()), SLOT(niggliReduce()));
  m_actions.push_back(m_niggliReduceAction);
  m_niggliReduceAction->setProperty("menu priority", 140);

  updateActions();
}

Crystal::~Crystal()
{
  if (m_unitCellDialog)
    m_unitCellDialog->deleteLater();

  qDeleteAll(m_actions);
  m_actions.clear();
}

QList<QAction*> Crystal::actions() const
{
  return m_actions;
}

QStringList Crystal::menuPath(QAction*) const
{
  return QStringList() << tr("&Crystal");
}

void Crystal::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule == mol)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = mol;
  if (m_unitCellDialog)
    m_unitCellDialog->setMolecule(m_molecule);

  if (m_molecule)
    connect(m_molecule, SIGNAL(changed(uint)), SLOT(moleculeChanged(uint)));

  updateActions();
}

void Crystal::moleculeChanged(unsigned int c)
{
  Q_ASSERT(m_molecule == qobject_cast<Molecule*>(sender()));

  Molecule::MoleculeChanges changes = static_cast<Molecule::MoleculeChanges>(c);

  if (changes & Molecule::UnitCell) {
    if (changes & Molecule::Added || changes & Molecule::Removed)
      updateActions();
  }
}

void Crystal::updateActions()
{
  // Disable everything for nullptr molecules.
  if (!m_molecule) {
    foreach (QAction* action, m_actions)
      action->setEnabled(false);
    return;
  }

  if (m_molecule->unitCell()) {
    foreach (QAction* action, m_actions)
      action->setEnabled(true);

    m_toggleUnitCellAction->setText(tr("Remove &Unit Cell"));
  } else {
    foreach (QAction* action, m_actions)
      action->setEnabled(false);

    m_importCrystalClipboardAction->setEnabled(true);
    m_toggleUnitCellAction->setEnabled(true);
    m_toggleUnitCellAction->setText(tr("Add &Unit Cell"));
  }
}

void Crystal::importCrystalClipboard()
{
  ImportCrystalDialog d;
  Core::Molecule m;
  if (d.importCrystalClipboard(m)) {
    // If we succeeded, update m_molecule
    Molecule::MoleculeChanges changes =
      Molecule::Added | Molecule::Atoms | Molecule::UnitCell;
    QString undoText = tr("Import Crystal from Clipboard");
    m_molecule->undoMolecule()->modifyMolecule(m, changes, undoText);
  }
}

void Crystal::editUnitCell()
{
  if (!m_unitCellDialog) {
    m_unitCellDialog = new UnitCellDialog(qobject_cast<QWidget*>(parent()));
    m_unitCellDialog->setMolecule(m_molecule);
  }

  m_unitCellDialog->show();
}

void Crystal::buildSupercell()
{
  SupercellDialog d;
  d.buildSupercell(*m_molecule);
}

void Crystal::niggliReduce()
{
  if (CrystalTools::isNiggliReduced(*m_molecule)) {
    QMessageBox::information(
      qobject_cast<QWidget*>(parent()), tr("Niggli Reduce Crystal"),
      tr("The unit cell is already reduced."), QMessageBox::Ok);
    return;
  }
  m_molecule->undoMolecule()->niggliReduceCell();
}

void Crystal::scaleVolume()
{
  if (!m_molecule->unitCell())
    return;

  VolumeScalingDialog dlg;
  dlg.setCurrentVolume(m_molecule->unitCell()->volume());
  int reply = dlg.exec();
  if (reply != QDialog::Accepted)
    return;

  m_molecule->undoMolecule()->setCellVolume(
    dlg.newVolume(),
    dlg.transformAtoms() ? CrystalTools::TransformAtoms : CrystalTools::None);
}

void Crystal::standardOrientation()
{
  m_molecule->undoMolecule()->rotateCellToStandardOrientation();
}

void Crystal::toggleUnitCell()
{
  if (m_molecule->unitCell()) {
    m_molecule->undoMolecule()->removeUnitCell();
  } else {
    m_molecule->undoMolecule()->addUnitCell();
    editUnitCell();
  }
}

void Crystal::wrapAtomsToCell()
{
  m_molecule->undoMolecule()->wrapAtomsToCell();
}

} // namespace QtPlugins
} // namespace Avogadro
