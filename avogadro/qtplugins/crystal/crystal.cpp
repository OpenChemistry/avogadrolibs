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

#include "unitcelldialog.h"
#include "volumescalingdialog.h"

#include <avogadro/core/unitcell.h>
#include <avogadro/core/crystaltools.h>
#include <avogadro/core/avospglib.h>

#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QAction>
#include <QtWidgets/QMessageBox>

#include <QtCore/QStringList>

using Avogadro::Core::CrystalTools;
using Avogadro::Core::AvoSpglib;
using Avogadro::Core::UnitCell;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

Crystal::Crystal(QObject *parent_) :
  Avogadro::QtGui::ExtensionPlugin(parent_),
  m_molecule(NULL),
  m_unitCellDialog(NULL),
  m_editUnitCellAction(new QAction(this)),
  m_niggliReduceAction(new QAction(this)),
  m_scaleVolumeAction(new QAction(this)),
  m_standardOrientationAction(new QAction(this)),
  m_toggleUnitCellAction(new QAction(this)),
  m_wrapAtomsToCellAction(new QAction(this)),
  m_fillUnitCell(new QAction(this)),
  m_perceiveSpaceGroup(new QAction(this)),
  m_primitiveReduce(new QAction(this)),
  m_symmetrizeCell(new QAction(this))
{
  // this will be changed when the molecule is set:
  m_toggleUnitCellAction->setText(tr("Toggle Unit Cell"));
  connect(m_toggleUnitCellAction, SIGNAL(triggered()), SLOT(toggleUnitCell()));
  m_actions.push_back(m_toggleUnitCellAction);
  m_toggleUnitCellAction->setProperty("menu priority", -1);

  m_editUnitCellAction->setText(tr("Edit Unit Cell..."));
  connect(m_editUnitCellAction, SIGNAL(triggered()), SLOT(editUnitCell()));
  m_actions.push_back(m_editUnitCellAction);
  m_editUnitCellAction->setProperty("menu priority", -50);

  m_wrapAtomsToCellAction->setText(tr("&Wrap Atoms to Unit Cell"));
  connect(m_wrapAtomsToCellAction, SIGNAL(triggered()),
          SLOT(wrapAtomsToCell()));
  m_actions.push_back(m_wrapAtomsToCellAction);
  m_wrapAtomsToCellAction->setProperty("menu priority", -200);

  m_standardOrientationAction->setText(tr("Rotate to Standard &Orientation"));
  connect(m_standardOrientationAction, SIGNAL(triggered()),
          SLOT(standardOrientation()));
  m_actions.push_back(m_standardOrientationAction);
  m_standardOrientationAction->setProperty("menu priority", -250);

  m_scaleVolumeAction->setText(tr("Scale Cell &Volume"));
  connect(m_scaleVolumeAction, SIGNAL(triggered()), SLOT(scaleVolume()));
  m_actions.push_back(m_scaleVolumeAction);
  m_scaleVolumeAction->setProperty("menu priority", -275);

  m_niggliReduceAction->setText(tr("Reduce Cell (&Niggli)"));
  connect(m_niggliReduceAction, SIGNAL(triggered()), SLOT(niggliReduce()));
  m_actions.push_back(m_niggliReduceAction);
  m_niggliReduceAction->setProperty("menu priority", -350);

  m_fillUnitCell->setText(tr("&Fill Unit Cell"));
  connect(m_fillUnitCell, SIGNAL(triggered()), SLOT(fillUnitCell()));
  m_actions.push_back(m_fillUnitCell);
  m_fillUnitCell->setProperty("menu priority", -370);

  m_perceiveSpaceGroup->setText(tr("Perceive Space Group"));
  connect(m_perceiveSpaceGroup, SIGNAL(triggered()), SLOT(perceiveSpaceGroup()));
  m_actions.push_back(m_perceiveSpaceGroup);
  m_perceiveSpaceGroup->setProperty("menu priority", -380);

  m_primitiveReduce->setText(tr("Reduce to primitive lattice"));
  connect(m_primitiveReduce, SIGNAL(triggered()), SLOT(primitiveReduce()));
  m_actions.push_back(m_primitiveReduce);
  m_primitiveReduce->setProperty("menu priority", -390);

  m_symmetrizeCell->setText(tr("Symmetrize Crystal"));
  connect(m_symmetrizeCell, SIGNAL(triggered()), SLOT(symmetrizeCell()));
  m_actions.push_back(m_symmetrizeCell);
  m_symmetrizeCell->setProperty("menu priority", -400);

  updateActions();
}

Crystal::~Crystal()
{
  if (m_unitCellDialog)
    m_unitCellDialog->deleteLater();

  qDeleteAll(m_actions);
  m_actions.clear();
}

QList<QAction *> Crystal::actions() const
{
  return m_actions;
}

QStringList Crystal::menuPath(QAction *) const
{
  return QStringList() << tr("&Crystal");
}

void Crystal::setMolecule(QtGui::Molecule *mol)
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

  Molecule::MoleculeChanges changes =
      static_cast<Molecule::MoleculeChanges>(c);

  if (changes & Molecule::UnitCell) {
    if (changes & Molecule::Added || changes & Molecule::Removed)
      updateActions();
  }
}

void Crystal::updateActions()
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

    m_toggleUnitCellAction->setText(tr("Remove &Unit Cell"));
  }
  else {
    foreach (QAction *action, m_actions)
      action->setEnabled(false);

    m_toggleUnitCellAction->setEnabled(true);
    m_toggleUnitCellAction->setText(tr("Add &Unit Cell"));
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

void Crystal::fillUnitCell()
{
  CrystalTools::fillUnitCell(*m_molecule);
  m_molecule->emitChanged(Molecule::Modified
                          | Molecule::Atoms | Molecule::UnitCell);

  /*if (CrystalTools::isFilled(*m_molecule)) {
    QMessageBox::information(qobject_cast<QWidget*>(parent()),
                             tr("Fill Unit Cell"),
                             tr("The unit cell is already filled."),
                             QMessageBox::Ok);
    return;
  }*/


}

void Crystal::primitiveReduce()
{
  CrystalTools::primitiveReduce(*m_molecule);
  m_molecule->emitChanged(Molecule::Modified
                          | Molecule::Atoms | Molecule::UnitCell);

}

void Crystal::symmetrizeCell()
{
  CrystalTools::symmetrizeCell(*m_molecule);
  m_molecule->emitChanged(Molecule::Modified
                          | Molecule::Atoms | Molecule::UnitCell);

}

void Crystal::perceiveSpaceGroup()
{

  //set information in unitCell
  CrystalTools::getSpacegroup(*m_molecule);
  m_molecule->emitChanged(Molecule::Modified
                          | Molecule::Atoms | Molecule::UnitCell);
}

void Crystal::niggliReduce()
{
  if (CrystalTools::isNiggliReduced(*m_molecule)) {
    QMessageBox::information(qobject_cast<QWidget*>(parent()),
                             tr("Niggli Reduce Crystal"),
                             tr("The unit cell is already reduced."),
                             QMessageBox::Ok);
    return;
  }
  CrystalTools::niggliReduce(*m_molecule, CrystalTools::TransformAtoms);
  CrystalTools::rotateToStandardOrientation(*m_molecule,
                                            CrystalTools::TransformAtoms);
  CrystalTools::wrapAtomsToUnitCell(*m_molecule);
  m_molecule->emitChanged(Molecule::Modified
                          | Molecule::Atoms | Molecule::UnitCell);
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

  CrystalTools::setVolume(*m_molecule, dlg.newVolume(),
                          dlg.transformAtoms() ? CrystalTools::TransformAtoms
                                               : CrystalTools::None);
  m_molecule->emitChanged(Molecule::Modified | Molecule::UnitCell
                          | (dlg.transformAtoms() ? Molecule::Atoms
                                                  : Molecule::NoChange));
}

void Crystal::standardOrientation()
{
  CrystalTools::rotateToStandardOrientation(*m_molecule,
                                            CrystalTools::TransformAtoms);
  m_molecule->emitChanged(Molecule::Modified
                          | Molecule::Atoms | Molecule::UnitCell);
}

void Crystal::toggleUnitCell()
{
  if (m_molecule->unitCell()) {
    m_molecule->setUnitCell(NULL);
    m_molecule->emitChanged(Molecule::UnitCell | Molecule::Removed);
  }
  else {
    UnitCell *cell = new UnitCell;
    cell->setCellParameters(static_cast<Real>(3.0),
                            static_cast<Real>(3.0),
                            static_cast<Real>(3.0),
                            static_cast<Real>(90.0) * DEG_TO_RAD,
                            static_cast<Real>(90.0) * DEG_TO_RAD,
                            static_cast<Real>(90.0) * DEG_TO_RAD);
    m_molecule->setUnitCell(cell);
    m_molecule->emitChanged(Molecule::UnitCell | Molecule::Added);
    editUnitCell();
  }
}

void Crystal::wrapAtomsToCell()
{
  CrystalTools::wrapAtomsToUnitCell(*m_molecule);
  m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);
}

} // namespace QtPlugins
} // namespace Avogadro
