/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013-2015 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "rwmolecule.h"
#include "rwmolecule_undo.h"

#include <algorithm>
#include <cassert>

#ifdef USE_SPGLIB
#include <avogadro/core/avospglib.h>
#endif
#include <avogadro/core/spacegroups.h>
#include <avogadro/qtgui/hydrogentools.h>

namespace Avogadro {
namespace QtGui {

using Core::Array;
using Core::AtomHybridization;
using Core::CrystalTools;
using Core::UnitCell;
using std::swap;

RWMolecule::RWMolecule(Molecule& mol, QObject* p) : QObject(p), m_molecule(mol)
{}

RWMolecule::~RWMolecule() {}

RWMolecule::AtomType RWMolecule::addAtom(unsigned char num, bool usingPositions)
{
  Index atomId = static_cast<Index>(m_molecule.atomCount());
  Index atomUid = static_cast<Index>(m_molecule.m_atomUniqueIds.size());

  AddAtomCommand* comm =
    new AddAtomCommand(*this, num, usingPositions, atomId, atomUid);
  comm->setText(tr("Add Atom"));
  m_undoStack.push(comm);
  return AtomType(this, atomId);
}

RWMolecule::AtomType RWMolecule::addAtom(unsigned char num,
                                         const Vector3& position3d)
{
  // We will combine the actions in this command.
  m_undoStack.beginMacro(tr("Add Atom"));
  AtomType atom = addAtom(num);
  setAtomPosition3d(atomCount() - 1, position3d);
  m_undoStack.endMacro();
  return atom;
}

Index RWMolecule::atomCount(unsigned char num) const
{
  return m_molecule.atomCount(num);
}

bool RWMolecule::removeAtom(Index atomId)
{
  if (atomId >= atomCount())
    return false;

  Index uniqueId = findAtomUniqueId(atomId);
  if (uniqueId == MaxIndex)
    return false;

  // Lump all operations into a single undo command:
  m_undoStack.beginMacro(tr("Remove Atom"));

  // Remove any bonds containing this atom first.
  Array<BondType> atomBonds = bonds(atomId);
  while (atomBonds.size()) {
    // Ensure that indices aren't invalidated as we remove them:
    assert("atomBonds have ascending indices" &&
           (atomBonds.size() == 1 ||
            ((atomBonds.end() - 2)->index() < (atomBonds.end() - 1)->index())));
    removeBond(atomBonds.back());
    atomBonds.pop_back();
  }

  RemoveAtomCommand* comm = new RemoveAtomCommand(
    *this, atomId, uniqueId, atomicNumber(atomId), atomPosition3d(atomId));
  comm->setText(tr("Remove Atom"));

  m_undoStack.push(comm);

  m_undoStack.endMacro();
  return true;
}

void RWMolecule::clearAtoms()
{
  m_undoStack.beginMacro(tr("Clear Atoms"));

  while (atomCount() != 0)
    removeAtom(0);

  m_undoStack.endMacro();
}

void RWMolecule::adjustHydrogens(Index atomId)
{
  RWAtom atom = this->atom(atomId);
  if (atom.isValid()) {
    m_undoStack.beginMacro(tr("Adjust Hydrogens"));
    QtGui::HydrogenTools::adjustHydrogens(atom);
    m_undoStack.endMacro();
  }
}

void RWMolecule::adjustHydrogens(const Core::Array<Index>& atomIds)
{
  m_undoStack.beginMacro(tr("Adjust Hydrogens"));
  for (Index i = 0; i < atomIds.size(); ++i) {
    adjustHydrogens(atomIds[i]);
  }
  m_undoStack.endMacro();
}

bool RWMolecule::setAtomicNumbers(const Core::Array<unsigned char>& nums)
{
  if (nums.size() != m_molecule.atomCount())
    return false;

  SetAtomicNumbersCommand* comm =
    new SetAtomicNumbersCommand(*this, m_molecule.atomicNumbers(), nums);
  comm->setText(tr("Change Elements"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setAtomicNumber(Index atomId, unsigned char num)
{
  if (atomId >= atomCount())
    return false;

  SetAtomicNumberCommand* comm = new SetAtomicNumberCommand(
    *this, atomId, m_molecule.atomicNumber(atomId), num);
  comm->setText(tr("Change Element"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setAtomPositions3d(const Core::Array<Vector3>& pos,
                                    const QString& undoText)
{
  if (pos.size() != m_molecule.atomCount())
    return false;

  SetPositions3dCommand* comm =
    new SetPositions3dCommand(*this, m_molecule.m_positions3d, pos);
  comm->setText(undoText);
  comm->setCanMerge(m_interactive);
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setLabel(Index atomId, const std::string& label,
                          const QString& undoText)
{
  ModifyLabelCommand* comm = new ModifyLabelCommand(*this, atomId, label);
  comm->setText(undoText);
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setAtomPosition3d(Index atomId, const Vector3& pos,
                                   const QString& undoText)
{
  if (atomId >= atomCount())
    return false;

  if (m_molecule.m_positions3d.size() != m_molecule.atomCount())
    m_molecule.m_positions3d.resize(m_molecule.atomCount(), Vector3::Zero());

  SetPosition3dCommand* comm = new SetPosition3dCommand(
    *this, atomId, m_molecule.m_positions3d[atomId], pos);
  comm->setText(undoText);
  comm->setCanMerge(m_interactive);
  m_undoStack.push(comm);
  return true;
}

void RWMolecule::setAtomSelected(Index atomId, bool selected)
{
  // FIXME: Add in an implementation (and use it from the selection tool).
  m_molecule.setAtomSelected(atomId, selected);
}

bool RWMolecule::atomSelected(Index atomId) const
{
  return m_molecule.atomSelected(atomId);
}

bool RWMolecule::setHybridization(Index atomId, Core::AtomHybridization hyb)
{
  if (atomId >= atomCount())
    return false;

  SetAtomicNumberCommand* comm = new SetAtomicNumberCommand(
    *this, atomId, m_molecule.hybridization(atomId), hyb);
  comm->setText(tr("Change Atom Hybridization"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setFormalCharge(Index atomId, signed char charge)
{
  if (atomId >= atomCount())
    return false;

  SetAtomFormalChargeCommand* comm = new SetAtomFormalChargeCommand(
    *this, atomId, m_molecule.formalCharge(atomId), charge);
  comm->setText(tr("Change Atom Formal Charge"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setColor(Index atomId, Vector3ub color)
{
  if (atomId >= atomCount())
    return false;

  SetAtomColorCommand* comm =
    new SetAtomColorCommand(*this, atomId, m_molecule.color(atomId), color);
  comm->setText(tr("Change Atom Color"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setLayer(Index atomId, size_t layer)
{
  if (atomId >= atomCount())
    return false;

  SetLayerCommand* comm =
    new SetLayerCommand(*this, atomId, m_molecule.layer(atomId), layer);
  comm->setText(tr("Change Atom Layer"));
  m_undoStack.push(comm);
  return true;
}

RWMolecule::BondType RWMolecule::addBond(Index atom1, Index atom2,
                                         unsigned char order)
{
  if (atom1 == atom2 || std::max(atom1, atom2) >= atomCount())
    return BondType();

  Index bondId = bondCount();
  Index bondUid = static_cast<Index>(m_molecule.m_bondUniqueIds.size());

  AddBondCommand* comm = new AddBondCommand(
    *this, order, Molecule::makeBondPair(atom1, atom2), bondId, bondUid);
  comm->setText(tr("Add Bond"));
  m_undoStack.push(comm);
  return BondType(this, bondId);
}

RWMolecule::BondType RWMolecule::bond(Index atom1, Index atom2) const
{
  Molecule::BondType b = m_molecule.bond(atom1, atom2);
  if (b.isValid())
    return BondType(const_cast<RWMolecule*>(this), b.index());
  else
    return BondType();
}

bool RWMolecule::removeBond(Index bondId)
{
  if (bondId >= bondCount())
    return false;

  Index bondUid = findBondUniqueId(bondId);
  if (bondUid == MaxIndex)
    return false;

  RemoveBondCommand* comm =
    new RemoveBondCommand(*this, bondId, bondUid, m_molecule.bondPair(bondId),
                          m_molecule.bondOrder(bondId));
  comm->setText(tr("Removed Bond"));
  m_undoStack.push(comm);
  return true;
}

void RWMolecule::clearBonds()
{
  m_undoStack.beginMacro(tr("Clear Bonds"));

  while (bondCount() != 0)
    removeBond(0);

  m_undoStack.endMacro();
}

bool RWMolecule::setBondOrders(const Core::Array<unsigned char>& orders)
{
  if (orders.size() != m_molecule.bondCount())
    return false;

  SetBondOrdersCommand* comm =
    new SetBondOrdersCommand(*this, m_molecule.bondOrders(), orders);
  comm->setText(tr("Set Bond Orders"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setBondOrder(Index bondId, unsigned char order)
{
  if (bondId >= bondCount())
    return false;

  SetBondOrderCommand* comm =
    new SetBondOrderCommand(*this, bondId, m_molecule.bondOrder(bondId), order);
  comm->setText(tr("Change Bond Order"));
  // Always allow merging, but only if bondId is the same.
  comm->setCanMerge(true);
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setBondPairs(const Array<std::pair<Index, Index>>& pairs)
{
  if (pairs.size() != m_molecule.bondCount())
    return false;

  // Correct any pairs that are ordered improperly:
  typedef std::pair<Index, Index> BondPair;
  Array<BondPair> p(pairs);
  // Use for reading to prevent copies unless needed (Array is copy-on-write):
  const Array<BondPair>& p_const = p;
  for (size_t i = 0; i < p.size(); ++i)
    if (p_const[i].first > p_const[i].second)
      swap(p[i].first, p[i].second);

  SetBondPairsCommand* comm =
    new SetBondPairsCommand(*this, m_molecule.bondPairs(), p);
  comm->setText(tr("Update Bonds"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setBondPair(Index bondId, const std::pair<Index, Index>& pair)
{
  if (bondId >= bondCount() || pair.first == pair.second)
    return false;

  SetBondPairCommand* comm = nullptr;
  if (pair.first < pair.second) {
    comm =
      new SetBondPairCommand(*this, bondId, m_molecule.bondPair(bondId), pair);
  } else {
    comm =
      new SetBondPairCommand(*this, bondId, m_molecule.bondPair(bondId),
                             Molecule::makeBondPair(pair.first, pair.second));
  }
  comm->setText(tr("Update Bond"));
  m_undoStack.push(comm);
  return true;
}

void RWMolecule::addUnitCell()
{
  // If there is already a unit cell, there is nothing to do
  if (m_molecule.unitCell())
    return;

  UnitCell* cell = new UnitCell;
  cell->setCellParameters(
    static_cast<Real>(3.0), static_cast<Real>(3.0), static_cast<Real>(3.0),
    static_cast<Real>(90.0) * DEG_TO_RAD, static_cast<Real>(90.0) * DEG_TO_RAD,
    static_cast<Real>(90.0) * DEG_TO_RAD);
  m_molecule.setUnitCell(cell);

  AddUnitCellCommand* comm =
    new AddUnitCellCommand(*this, *m_molecule.unitCell());
  comm->setText(tr("Add Unit Cell"));
  m_undoStack.push(comm);
  emitChanged(Molecule::UnitCell | Molecule::Added);
}

void RWMolecule::removeUnitCell()
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return;

  RemoveUnitCellCommand* comm =
    new RemoveUnitCellCommand(*this, *m_molecule.unitCell());
  comm->setText(tr("Remove Unit Cell"));
  m_undoStack.push(comm);

  m_molecule.setUnitCell(nullptr);
  emitChanged(Molecule::UnitCell | Molecule::Removed);
}

void RWMolecule::modifyMolecule(const Molecule& newMolecule,
                                Molecule::MoleculeChanges changes,
                                const QString& undoText)
{
  ModifyMoleculeCommand* comm =
    new ModifyMoleculeCommand(*this, m_molecule, newMolecule);

  comm->setText(undoText);
  m_undoStack.push(comm);

  m_molecule = newMolecule;
  emitChanged(changes);
}

void RWMolecule::appendMolecule(const Molecule& mol, const QString& undoText)
{
  // We add atoms and bonds, nothing else
  Molecule::MoleculeChanges changes =
    (Molecule::Atoms | Molecule::Bonds | Molecule::Added);

  beginMergeMode(undoText);
  // loop through and add the atoms
  Index offset = atomCount();
  for (size_t i = 0; i < mol.atomCount(); ++i) {
    Core::Atom atom = mol.atom(i);
    addAtom(atom.atomicNumber(), atom.position3d());
    setAtomSelected(atomCount() - 1, true);
  }
  // now loop through and add the bonds
  for (size_t i = 0; i < mol.bondCount(); ++i) {
    Core::Bond bond = mol.bond(i);
    addBond(bond.atom1().index() + offset, bond.atom2().index() + offset,
            bond.order());
  }
  endMergeMode();
  emitChanged(changes);
}

void RWMolecule::editUnitCell(Matrix3 cellMatrix, CrystalTools::Options options)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return;

  // Make a copy of the molecule to edit so we can store the old one
  // If the user has "TransformAtoms" set in the options, then
  // the atom positions will move as well.
  Molecule newMolecule = m_molecule;
  CrystalTools::setCellMatrix(newMolecule, cellMatrix, options);

  // We will just modify the whole molecule since there may be many changes
  Molecule::MoleculeChanges changes = Molecule::UnitCell | Molecule::Modified;
  // If TransformAtoms is set in the options, then the atoms may be modified
  // as well.
  if (options & CrystalTools::TransformAtoms)
    changes |= Molecule::Atoms | Molecule::Modified;
  QString undoText = tr("Edit Unit Cell");

  modifyMolecule(newMolecule, changes, undoText);
}

void RWMolecule::wrapAtomsToCell()
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return;

  Core::Array<Vector3> oldPos = m_molecule.atomPositions3d();
  CrystalTools::wrapAtomsToUnitCell(m_molecule);
  Core::Array<Vector3> newPos = m_molecule.atomPositions3d();

  SetPositions3dCommand* comm =
    new SetPositions3dCommand(*this, oldPos, newPos);
  comm->setText(tr("Wrap Atoms to Cell"));
  m_undoStack.push(comm);

  Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Modified;
  emitChanged(changes);
}

void RWMolecule::setCellVolume(double newVolume, CrystalTools::Options options)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return;

  // Make a copy of the molecule to edit so we can store the old one
  // The unit cell and atom positions may change
  Molecule newMolecule = m_molecule;

  CrystalTools::setVolume(newMolecule, newVolume, options);

  // We will just modify the whole molecule since there may be many changes
  Molecule::MoleculeChanges changes = Molecule::UnitCell | Molecule::Modified;
  if (options & CrystalTools::TransformAtoms)
    changes |= Molecule::Atoms | Molecule::Modified;
  QString undoText = tr("Scale Cell Volume");

  modifyMolecule(newMolecule, changes, undoText);
}

void RWMolecule::buildSupercell(unsigned int a, unsigned int b, unsigned int c)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return;

  // Make a copy of the molecule to edit so we can store the old one
  // The unit cell and atom positions may change
  Molecule newMolecule = m_molecule;

  CrystalTools::buildSupercell(newMolecule, a, b, c);

  // We will just modify the whole molecule since there may be many changes
  Molecule::MoleculeChanges changes =
    Molecule::UnitCell | Molecule::Modified | Molecule::Atoms | Molecule::Added;
  QString undoText = tr("Build Super Cell");

  modifyMolecule(newMolecule, changes, undoText);
}

void RWMolecule::niggliReduceCell()
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return;

  // Make a copy of the molecule to edit so we can store the old one
  // The unit cell and atom positions may change
  Molecule newMolecule = m_molecule;

  // We need to perform all three of these operations...
  CrystalTools::niggliReduce(newMolecule, CrystalTools::TransformAtoms);
  CrystalTools::rotateToStandardOrientation(newMolecule,
                                            CrystalTools::TransformAtoms);
  CrystalTools::wrapAtomsToUnitCell(newMolecule);

  // We will just modify the whole molecule since there may be many changes
  Molecule::MoleculeChanges changes =
    Molecule::UnitCell | Molecule::Atoms | Molecule::Modified;
  QString undoText = tr("Niggli Reduction");

  modifyMolecule(newMolecule, changes, undoText);
}

void RWMolecule::rotateCellToStandardOrientation()
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return;

  // Store a copy of the old molecule
  // The atom positions may move as well.
  Molecule newMolecule = m_molecule;

  CrystalTools::rotateToStandardOrientation(newMolecule,
                                            CrystalTools::TransformAtoms);

  // Since most components of the molecule will be modified (atom positions
  // and the unit cell), we will just modify the whole thing...
  Molecule::MoleculeChanges changes =
    Molecule::UnitCell | Molecule::Atoms | Molecule::Modified;
  QString undoText = tr("Rotate to Standard Orientation");

  modifyMolecule(newMolecule, changes, undoText);
}

bool RWMolecule::reduceCellToPrimitive(double cartTol)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return false;

  // Make a copy of the molecule to edit so we can store the old one
  // The unit cell, atom positions, and numbers of atoms may change
  Molecule newMolecule = m_molecule;
#ifdef USE_SPGLIB
  if (!Core::AvoSpglib::reduceToPrimitive(newMolecule, cartTol))
    return false;
#else
  return false;
#endif

  // Since most components of the molecule will be modified,
  // we will just modify the whole thing...
  Molecule::MoleculeChanges changes =
    Molecule::UnitCell | Molecule::Atoms | Molecule::Added;
  QString undoText = tr("Reduce to Primitive");

  modifyMolecule(newMolecule, changes, undoText);
  return true;
}

bool RWMolecule::conventionalizeCell(double cartTol)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return false;

  // Make a copy of the molecule to edit so we can store the old one
  // The unit cell, atom positions, and numbers of atoms may all change
  Molecule newMolecule = m_molecule;

#ifdef USE_SPGLIB
  if (!Core::AvoSpglib::conventionalizeCell(newMolecule, cartTol))
    return false;
#else
  return false;
#endif

  Molecule::MoleculeChanges changes =
    Molecule::UnitCell | Molecule::Atoms | Molecule::Added;
  QString undoText = tr("Conventionalize Cell");

  modifyMolecule(newMolecule, changes, undoText);
  return true;
}

bool RWMolecule::symmetrizeCell(double cartTol)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return false;

  // Make a copy of the molecule to edit so we can store the old one
  // The unit cell, atom positions, and numbers of atoms may all change
  Molecule newMolecule = m_molecule;

#ifdef USE_SPGLIB
  if (!Core::AvoSpglib::symmetrize(newMolecule, cartTol))
    return false;
#else
  return false;
#endif

  Molecule::MoleculeChanges changes =
    Molecule::UnitCell | Molecule::Atoms | Molecule::Added;
  QString undoText = tr("Symmetrize Cell");

  modifyMolecule(newMolecule, changes, undoText);
  return true;
}

bool RWMolecule::fillUnitCell(unsigned short hallNumber, double cartTol)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return false;

  // Make a copy of the molecule to edit so we can store the old one
  // The atom positions and numbers of atoms may change
  Molecule newMolecule = m_molecule;

  Core::SpaceGroups::fillUnitCell(newMolecule, hallNumber, cartTol);

  Molecule::MoleculeChanges changes = Molecule::Added | Molecule::Atoms;
  QString undoText = tr("Fill Unit Cell");

  modifyMolecule(newMolecule, changes, undoText);
  return true;
}

bool RWMolecule::reduceCellToAsymmetricUnit(unsigned short hallNumber,
                                            double cartTol)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return false;

  // Make a copy of the molecule to edit so we can store the old one
  // The atom positions and numbers of atoms may change
  Molecule newMolecule = m_molecule;

  Core::SpaceGroups::reduceToAsymmetricUnit(newMolecule, hallNumber, cartTol);

  Molecule::MoleculeChanges changes = Molecule::Removed | Molecule::Atoms;
  QString undoText = tr("Reduce Cell to Asymmetric Unit");

  modifyMolecule(newMolecule, changes, undoText);
  return true;
}

void RWMolecule::emitChanged(unsigned int change)
{
  m_molecule.emitChanged(change);
}

Index RWMolecule::findAtomUniqueId(Index atomId) const
{
  return m_molecule.findAtomUniqueId(atomId);
}

Index RWMolecule::findBondUniqueId(Index bondId) const
{
  return m_molecule.findBondUniqueId(bondId);
}

bool RWMolecule::setForceVector(Index atomId, const Vector3& forces,
                                const QString& undoText)
{
  if (atomId >= atomCount())
    return false;

  if (m_molecule.m_positions3d.size() != m_molecule.atomCount())
    m_molecule.m_positions3d.resize(m_molecule.atomCount(), Vector3::Zero());

  SetForceVectorCommand* comm = new SetForceVectorCommand(
    *this, atomId, m_molecule.m_positions3d[atomId], forces);
  comm->setText(undoText);
  comm->setCanMerge(m_interactive);
  m_undoStack.push(comm);
  return true;
}

} // namespace QtGui
} // namespace Avogadro
