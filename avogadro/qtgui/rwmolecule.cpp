/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "rwmolecule.h"
#include "rwmolecule_undo.h"

#include "gaussiansetconcurrent.h"
#include "meshgenerator.h"
#include "slatersetconcurrent.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <set>

#ifdef USE_SPGLIB
#include <avogadro/core/avospglib.h>
#endif
#include <avogadro/core/layermanager.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/qtgui/hydrogentools.h>

#include <QtCore/QDebug>

namespace Avogadro::QtGui {

using Core::Array;
using Core::AtomHybridization;
using Core::CrystalTools;
using Core::UnitCell;
using std::swap;

RWMolecule::RWMolecule(Molecule& mol, QObject* p)
  : QObject(p), m_molecule(mol), m_interactive(false)
{
}

RWMolecule::~RWMolecule() {}

RWMolecule::AtomType RWMolecule::addAtom(unsigned char num, bool usingPositions)
{
  auto atomId = static_cast<Index>(m_molecule.atomCount());
  auto atomUid = static_cast<Index>(m_molecule.m_atomUniqueIds.size());

  auto* comm = new AddAtomCommand(*this, num, usingPositions, atomId, atomUid);
  comm->setText(tr("Add Atom"));
  m_undoStack.push(comm);
  return AtomType(this, atomId);
}

RWMolecule::AtomType RWMolecule::addAtom(unsigned char num,
                                         const Vector3& position3d)
{
  // One command that adds the atom already in place: its position goes into
  // every coordinate set at the same time, and undoing it removes the atom
  // from all of them.
  auto atomId = static_cast<Index>(m_molecule.atomCount());
  auto atomUid = static_cast<Index>(m_molecule.m_atomUniqueIds.size());

  auto* comm =
    new AddAtomCommand(*this, num, true, atomId, atomUid, position3d);
  comm->setText(tr("Add Atom"));
  m_undoStack.push(comm);
  return AtomType(this, atomId);
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
  while (!atomBonds.empty()) {
    // Ensure that indices aren't invalidated as we remove them:
    assert("atomBonds have ascending indices" &&
           (atomBonds.size() == 1 ||
            ((atomBonds.end() - 2)->index() < (atomBonds.end() - 1)->index())));
    removeBond(atomBonds.back());
    atomBonds.pop_back();
  }

  auto* comm = new RemoveAtomCommand(*this, atomId, uniqueId);
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

bool RWMolecule::reorderAtoms(const Core::Array<Index>& newOrder)
{
  const Index count = atomCount();
  if (newOrder.size() != count)
    return false;

  // Check that this really is a permutation before touching the molecule. A
  // repeated or out-of-range entry would copy one atom's data over another's
  // and leave no way back.
  std::vector<bool> seen(count, false);
  for (Index i = 0; i < count; ++i) {
    const Index from = newOrder[i];
    if (from >= count || seen[from])
      return false;
    seen[from] = true;
  }

  // Decompose the permutation into transpositions. current[i] is the
  // original index of the atom now sitting at i, and where[] is its inverse,
  // so the atom wanted at each position is found without searching for it.
  std::vector<Index> current(count);
  std::vector<Index> where(count);
  for (Index i = 0; i < count; ++i) {
    current[i] = i;
    where[i] = i;
  }

  std::vector<std::pair<Index, Index>> swaps;
  for (Index i = 0; i < count; ++i) {
    const Index wanted = newOrder[i];
    const Index j = where[wanted];
    if (j == i)
      continue; // already in place
    const Index displaced = current[i];
    swaps.emplace_back(i, j);
    std::swap(current[i], current[j]);
    where[wanted] = i;
    where[displaced] = j;
  }

  if (swaps.empty())
    return true; // the molecule is already in this order

  auto* comm = new ReorderAtomsCommand(*this, swaps);
  comm->setText(tr("Reorder Atoms"));
  // ReorderAtomsCommand::redo() -- run synchronously by push() -- already
  // emits Atoms|Bonds|Modified|Reordered itself (see the class comment in
  // rwmolecule_undo.h), so no further emit is needed here; one would both
  // duplicate the notification and drop the Reordered flag from it.
  m_undoStack.push(comm);

  return true;
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

  // convert the indexes to unique ids
  // since we're adding and removing atoms
  // (so the index will change)
  Core::Array<Index> uniqueIds;
  for (auto id : atomIds) {
    Index uniqueId = findAtomUniqueId(id);
    if (uniqueId != MaxIndex)
      uniqueIds.push_back(uniqueId);
  }

  for (auto uniqueId : uniqueIds) {
    RWAtom atom = this->atomByUniqueId(uniqueId);
    if (atom.isValid()) {
      QtGui::HydrogenTools::adjustHydrogens(atom);
    }
  }
  m_undoStack.endMacro();
}

bool RWMolecule::setAtomicNumbers(const Core::Array<unsigned char>& nums)
{
  if (nums.size() != m_molecule.atomCount())
    return false;

  auto* comm = new SetArrayCommand<unsigned char>(
    *this,
    [](Molecule& mol, const Array<unsigned char>& values) {
      mol.setAtomicNumbers(values);
    },
    m_molecule.atomicNumbers(), nums);
  comm->setText(tr("Change Elements"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setAtomicNumber(Index atomId, unsigned char num)
{
  if (atomId >= atomCount())
    return false;

  auto* comm = new SetAtomicNumberCommand(*this, atomId,
                                          m_molecule.atomicNumber(atomId), num);
  comm->setText(tr("Change Element"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setAtomPositions3d(const Core::Array<Vector3>& pos,
                                    const QString& undoText)
{
  if (pos.size() != m_molecule.atomCount())
    return false;

  // This assigns the array rather than calling a Molecule setter, which
  // would check the size and emit a change.
  auto* comm = new SetArrayCommand<Vector3>(
    *this,
    [](Molecule& mol, const Array<Vector3>& values) {
      mol.atomPositions3d() = values;
    },
    m_molecule.m_positions3d, pos);
  comm->setText(undoText);
  comm->setMergeId(m_interactive ? SetPositions3dMergeId : -1);
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setAtomLabel(Index atomId, const std::string& label,
                              const QString& undoText)
{
  if (atomId >= atomCount())
    return false;

  auto* comm = new SetEntryCommand<std::string>(
    *this,
    [](Molecule& mol, Index index, const std::string& value) {
      mol.setAtomLabel(index, value);
    },
    atomId, m_molecule.atomLabel(atomId), label);
  comm->setText(undoText);
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setBondLabel(Index bondId, const std::string& label,
                              const QString& undoText)
{
  if (bondId >= bondCount())
    return false;

  auto* comm = new SetEntryCommand<std::string>(
    *this,
    [](Molecule& mol, Index index, const std::string& value) {
      mol.setBondLabel(index, value);
    },
    bondId, m_molecule.bondLabel(bondId), label);
  comm->setText(undoText);
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setAtomPosition3d(Index atomId, const Vector3& pos,
                                   const QString& undoText)
{
  if (atomId >= atomCount() || !SetEntriesCommand<Vector3>::canStore(atomId))
    return false;

  auto* comm = new SetEntriesCommand<Vector3>(
    *this,
    [](Molecule& mol, Index index, const Vector3& value) {
      // The array may be shorter than the atom count (an atom added without
      // a position, possibly by a redo); setting a position fills it out.
      Array<Vector3>& positions = mol.atomPositions3d();
      if (positions.size() < mol.atomCount())
        positions.resize(mol.atomCount(), Vector3::Zero());
      if (index < positions.size())
        positions[index] = value;
    },
    atomId, m_molecule.atomPosition3d(atomId), pos);
  comm->setText(undoText);
  comm->setMergeId(m_interactive ? SetPosition3dMergeId : -1);
  m_undoStack.push(comm);
  return true;
}

void RWMolecule::setAtomSelected(Index atomId, bool selected,
                                 const QString& undoText)
{
  // A caller holding an index from before an atom was removed would other-
  // wise write past the end of the selection bitfield, corrupting whatever
  // follows it rather than failing where the mistake was made.
  if (atomId >= atomCount() || !SetEntriesCommand<bool>::canStore(atomId))
    return;

  // Selecting an already-selected atom (or deselecting an unselected one)
  // changes nothing, so it must not leave an undo step that does nothing --
  // e.g. "select all" twice, or a select-by-element with no matches.
  if (m_molecule.atomSelected(atomId) == selected)
    return;

  auto* comm = new SetEntriesCommand<bool>(
    *this,
    [](Molecule& mol, Index index, const bool& value) {
      // Out-of-range indices are refused by the molecule.
      mol.setAtomSelected(index, value);
    },
    atomId, m_molecule.atomSelected(atomId), selected);
  comm->setText(undoText);
  comm->setMergeId(ModifySelectionMergeId);
  m_undoStack.push(comm);
}

bool RWMolecule::atomSelected(Index atomId) const
{
  return m_molecule.atomSelected(atomId);
}

bool RWMolecule::setHybridization(Index atomId, Core::AtomHybridization hyb)
{
  if (atomId >= atomCount())
    return false;

  auto* comm = new SetEntryCommand<Core::AtomHybridization>(
    *this,
    [](Molecule& mol, Index index, const Core::AtomHybridization& value) {
      mol.setHybridization(index, value);
    },
    atomId, m_molecule.hybridization(atomId), hyb);
  comm->setText(tr("Change Atom Hybridization"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setFormalCharge(Index atomId, signed char charge)
{
  if (atomId >= atomCount())
    return false;

  auto* comm = new SetEntryCommand<signed char>(
    *this,
    [](Molecule& mol, Index index, const signed char& value) {
      mol.setFormalCharge(index, value);
    },
    atomId, m_molecule.formalCharge(atomId), charge);
  comm->setText(tr("Change Atom Formal Charge"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setOccupancy(Index atomId, double occupancy)
{
  if (atomId >= atomCount() || !std::isfinite(occupancy) || occupancy < 0.0)
    return false;

  // As for the 2D positions: the first edit of a short or empty column grows
  // it to the atom count, so keep the whole array to let undo restore its
  // shape (a molecule without occupancies must not seem to have them). The
  // values come only from here, already validated.
  const Array<double>& current = m_molecule.occupancies();
  if (current.size() != atomCount()) {
    Array<double> grown(current);
    grown.resize(atomCount(), 1.0);
    grown[atomId] = occupancy;
    auto* comm = new SetArrayCommand<double>(
      *this,
      [](Molecule& mol, const Array<double>& values) {
        mol.occupancies() = values;
        // as for the isotope: nothing else refreshes a view of the occupancy
        mol.emitChanged(Molecule::Atoms | Molecule::Properties);
      },
      current, grown);
    comm->setText(tr("Change Atom Occupancy"));
    m_undoStack.push(comm);
    return true;
  }

  auto* comm = new SetEntryCommand<double>(
    *this,
    [](Molecule& mol, Index index, const double& value) {
      mol.setOccupancy(index, value);
      mol.emitChanged(Molecule::Atoms | Molecule::Properties);
    },
    atomId, m_molecule.occupancy(atomId), occupancy);
  comm->setText(tr("Change Atom Occupancy"));
  m_undoStack.push(comm);
  return true;
}

namespace {
// Sets both disorder arrays of a molecule, and puts back both old arrays
// exactly (an empty or short column stays so).
class SetDisorderArraysCommand : public RWMolecule::UndoCommand
{
public:
  SetDisorderArraysCommand(RWMolecule& m,
                           const Array<std::string>& oldAssemblies,
                           const Array<std::string>& oldGroups,
                           const Array<std::string>& newAssemblies,
                           const Array<std::string>& newGroups)
    : UndoCommand(m), m_oldAssemblies(oldAssemblies), m_oldGroups(oldGroups),
      m_newAssemblies(newAssemblies), m_newGroups(newGroups)
  {
  }

  void redo() override { apply(m_newAssemblies, m_newGroups); }
  void undo() override { apply(m_oldAssemblies, m_oldGroups); }

private:
  void apply(const Array<std::string>& assemblies,
             const Array<std::string>& groups)
  {
    m_molecule.disorderAssemblies() = assemblies;
    m_molecule.disorderGroups() = groups;
    // as for the occupancy: nothing else refreshes a view of the labels
    m_molecule.emitChanged(Molecule::Atoms | Molecule::Properties);
  }

  Array<std::string> m_oldAssemblies;
  Array<std::string> m_oldGroups;
  Array<std::string> m_newAssemblies;
  Array<std::string> m_newGroups;
};
} // namespace

bool RWMolecule::setDisorder(Index atomId, const std::string& assembly,
                             const std::string& group)
{
  if (atomId >= atomCount())
    return false;

  // As for the occupancy, setting one atom grows a short or empty column to
  // the atom count, so keep both whole arrays to let undo restore their
  // shapes exactly.
  const Index count = atomCount();
  const Array<std::string>& assemblies = m_molecule.disorderAssemblies();
  const Array<std::string>& groups = m_molecule.disorderGroups();
  if (assemblies.size() == count && groups.size() == count) {
    // whole columns: only the entries change (a large edit stores no arrays)
    using Labels = std::pair<std::string, std::string>;
    auto* entry = new SetEntryCommand<Labels>(
      *this,
      [](Molecule& mol, Index index, const Labels& value) {
        mol.setDisorder(index, value.first, value.second);
        mol.emitChanged(Molecule::Atoms | Molecule::Properties);
      },
      atomId, Labels(assemblies[atomId], groups[atomId]),
      Labels(assembly, group));
    entry->setText(tr("Change Atom Disorder"));
    m_undoStack.push(entry);
    return true;
  }
  Array<std::string> grownAssemblies(assemblies);
  Array<std::string> grownGroups(groups);
  if (grownAssemblies.size() < count)
    grownAssemblies.resize(count);
  if (grownGroups.size() < count)
    grownGroups.resize(count);
  grownAssemblies[atomId] = assembly;
  grownGroups[atomId] = group;
  auto* comm = new SetDisorderArraysCommand(*this, assemblies, groups,
                                            grownAssemblies, grownGroups);
  comm->setText(tr("Change Atom Disorder"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setForceVector(Index atomId, const Vector3& force)
{
  if (atomId >= atomCount())
    return false;

  auto* comm = new SetEntryCommand<Vector3>(
    *this,
    [](Molecule& mol, Index index, const Vector3& value) {
      mol.setForceVector(index, value);
    },
    atomId, m_molecule.forceVector(atomId), force);
  comm->setText(tr("Change Force Vector"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setIsotope(Index atomId, unsigned short isotope)
{
  if (atomId >= atomCount())
    return false;

  auto* comm = new SetEntryCommand<unsigned short>(
    *this,
    [](Molecule& mol, Index index, const unsigned short& value) {
      mol.setIsotope(index, value);
      // An undo or redo has no other notice that would refresh a view of
      // the isotope, such as the atom property table.
      mol.emitChanged(Molecule::Atoms | Molecule::Properties);
    },
    atomId, m_molecule.isotope(atomId), isotope);
  comm->setText(tr("Change Atom Isotope"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setAtomPosition2d(Index atomId, const Vector2& pos)
{
  if (atomId >= atomCount())
    return false;

  // The 2D positions may be shorter than the atom count (or empty); the
  // molecule's setter and getter treat a missing entry as the origin. Setting
  // one entry of such an array grows it to the atom count, and undoing only
  // that entry would leave the grown array behind: a molecule without 2D
  // coordinates would then seem to have them, all at the origin. So the
  // first edit keeps the whole array, and undo puts back its shape as well.
  const Array<Vector2>& current = m_molecule.atomPositions2d();
  if (current.size() != atomCount()) {
    Array<Vector2> grown(current);
    grown.resize(atomCount(), Vector2::Zero());
    grown[atomId] = pos;
    auto* comm = new SetArrayCommand<Vector2>(
      *this,
      [](Molecule& mol, const Array<Vector2>& values) {
        mol.atomPositions2d() = values;
      },
      current, grown);
    comm->setText(tr("Change 2D Position"));
    m_undoStack.push(comm);
    return true;
  }

  auto* comm = new SetEntryCommand<Vector2>(
    *this,
    [](Molecule& mol, Index index, const Vector2& value) {
      mol.setAtomPosition2d(index, value);
    },
    atomId, m_molecule.atomPosition2d(atomId), pos);
  comm->setText(tr("Change 2D Position"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setColor(Index atomId, Vector3ub color)
{
  if (atomId >= atomCount())
    return false;

  auto* comm = new SetEntryCommand<Vector3ub>(
    *this,
    [](Molecule& mol, Index index, const Vector3ub& value) {
      mol.setColor(index, value);
    },
    atomId, m_molecule.color(atomId), color);
  comm->setText(tr("Change Atom Color"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setResidueColor(Index residueId, Vector3ub color)
{
  if (residueId >= m_molecule.residueCount())
    return false;

  auto* comm = new SetEntryCommand<Vector3ub>(
    *this,
    [](Molecule& mol, Index index, const Vector3ub& value) {
      mol.residue(index).setColor(value);
    },
    residueId, m_molecule.residue(residueId).color(), color);
  comm->setText(tr("Change Residue Color"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setLayer(Index atomId, size_t layer)
{
  if (atomId >= atomCount())
    return false;

  auto* comm = new SetEntryCommand<size_t>(
    *this,
    [](Molecule& mol, Index index, const size_t& value) {
      mol.setLayer(index, value);
    },
    atomId, m_molecule.layer(atomId), layer);
  comm->setText(tr("Change Atom Layer"));
  m_undoStack.push(comm);
  return true;
}

RWMolecule::BondType RWMolecule::addBond(Index atom1, Index atom2,
                                         unsigned char order)
{
  if (atom1 == atom2 || std::max(atom1, atom2) >= atomCount())
    return BondType();

  // Two atoms that are already bonded do not get a second bond:
  // Core::Molecule::addBond() updates the order and returns the existing bond,
  // so an AddBondCommand here would record a bond id one past the end and a
  // unique id for a bond that is never created. Change the order instead,
  // which is what the core call would have done, and keep it undoable.
  BondType existing = bond(atom1, atom2);
  if (existing.isValid()) {
    if (bondOrder(existing.index()) != order)
      setBondOrder(existing.index(), order);
    return existing;
  }

  Index bondId = bondCount();
  auto bondUid = static_cast<Index>(m_molecule.m_bondUniqueIds.size());

  auto* comm = new AddBondCommand(
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

  auto* comm = new RemoveBondCommand(*this, bondId, bondUid);
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

  auto* comm = new SetArrayCommand<unsigned char>(
    *this,
    [](Molecule& mol, const Array<unsigned char>& values) {
      mol.setBondOrders(values);
    },
    m_molecule.bondOrders(), orders);
  comm->setText(tr("Set Bond Orders"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setBondOrder(Index bondId, unsigned char order)
{
  if (bondId >= bondCount())
    return false;

  auto* comm = new SetEntryCommand<unsigned char>(
    *this,
    [](Molecule& mol, Index index, const unsigned char& value) {
      mol.setBondOrder(index, value);
    },
    bondId, m_molecule.bondOrder(bondId), order);
  comm->setText(tr("Change Bond Order"));
  // Always allow merging, but only if bondId is the same.
  comm->setMergeId(SetBondOrderMergeId);
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setBondPairs(const Array<std::pair<Index, Index>>& pairs)
{
  if (pairs.size() != m_molecule.bondCount())
    return false;

  // Correct any pairs that are ordered improperly, and refuse the whole set
  // (without touching the undo stack) if the core would: out of range
  // vertices, self-bonds or duplicate pairs.
  using BondPair = std::pair<Index, Index>;
  Array<BondPair> p(pairs);
  std::set<BondPair> seen;
  for (size_t i = 0; i < p.size(); ++i) {
    BondPair& pair = p[i];
    if (pair.first > pair.second)
      swap(pair.first, pair.second);
    if (pair.second >= m_molecule.atomCount() || pair.first == pair.second ||
        !seen.insert(pair).second)
      return false;
  }

  auto* comm = new SetArrayCommand<BondPair>(
    *this,
    [](Molecule& mol, const Array<BondPair>& values) {
      mol.setBondPairs(values);
    },
    m_molecule.bondPairs(), p);
  comm->setText(tr("Update Bonds"));
  m_undoStack.push(comm);
  return true;
}

bool RWMolecule::setBondPair(Index bondId, const std::pair<Index, Index>& pair)
{
  if (bondId >= bondCount() || pair.first == pair.second ||
      pair.first >= atomCount() || pair.second >= atomCount())
    return false;

  const std::pair<Index, Index> newPair =
    Molecule::makeBondPair(pair.first, pair.second);
  const std::pair<Index, Index> oldPair = m_molecule.bondPair(bondId);
  // The stored pair is not always ordered (removeAtom() renumbers atoms
  // without re-sorting), so compare the endpoints as an unordered pair.
  if (newPair == Molecule::makeBondPair(oldPair.first, oldPair.second))
    return true; // nothing to change
  // Another bond already joins these atoms: the core would refuse.
  if (m_molecule.graph().containsEdge(newPair.first, newPair.second))
    return false;

  auto* comm = new SetEntryCommand<std::pair<Index, Index>>(
    *this,
    [](Molecule& mol, Index index, const std::pair<Index, Index>& value) {
      mol.setBondPair(index, value);
    },
    bondId, oldPair, newPair);
  comm->setText(tr("Update Bond"));
  m_undoStack.push(comm);
  return true;
}

void RWMolecule::addUnitCell()
{
  // If there is already a unit cell, there is nothing to do
  if (m_molecule.unitCell())
    return;

  auto* cell = new UnitCell;
  cell->setCellParameters(
    static_cast<Real>(3.0), static_cast<Real>(3.0), static_cast<Real>(3.0),
    static_cast<Real>(90.0) * DEG_TO_RAD, static_cast<Real>(90.0) * DEG_TO_RAD,
    static_cast<Real>(90.0) * DEG_TO_RAD);
  m_molecule.setUnitCell(cell);

  auto* comm = new AddUnitCellCommand(*this, *m_molecule.unitCell());
  comm->setText(tr("Add Unit Cell…"));
  m_undoStack.push(comm);
  emitChanged(Molecule::UnitCell | Molecule::Added);
}

void RWMolecule::removeUnitCell()
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return;

  auto* comm = new RemoveUnitCellCommand(*this, *m_molecule.unitCell());
  comm->setText(tr("Remove Unit Cell"));
  m_undoStack.push(comm);

  m_molecule.setUnitCell(nullptr);
  emitChanged(Molecule::UnitCell | Molecule::Removed);
}

void RWMolecule::cancelBackgroundCalculations()
{
  GaussianSetConcurrent::cancelAllCalculations();
  SlaterSetConcurrent::cancelAllCalculations();
  MeshGenerator::cancelAllCalculations();
}

void RWMolecule::modifyMolecule(const Molecule& newMolecule,
                                Molecule::MoleculeChanges changes,
                                const QString& undoText)
{
  // Both copies below read the current molecule's cubes, meshes and basis
  // set, which an orbital or surface calculation may still be writing.
  cancelBackgroundCalculations();

  // A replacement that arrives with no display state of its own (anything
  // freshly read from a file or script) would switch off every display type,
  // so it inherits the current molecule's. Done on a copy, before the command
  // is built, so redo restores it as well.
  const Molecule* replacement = &newMolecule;
  Molecule withDisplayState;
  if (newMolecule.layerInfo()->enable.empty()) {
    withDisplayState = newMolecule;
    withDisplayState.copyDisplayStateFrom(m_molecule);
    replacement = &withDisplayState;
  }

  auto* comm = new ModifyMoleculeCommand(*this, m_molecule, *replacement);

  comm->setText(undoText);
  // push() runs redo(), which cancels any worker still using the data being
  // replaced and assigns the new molecule.
  m_undoStack.push(comm);

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
  const bool hasOccupancies = !mol.occupancies().empty();
  const bool hasDisorder = !mol.disorderGroups().empty();
  for (size_t i = 0; i < mol.atomCount(); ++i) {
    Core::Atom atom = mol.atom(i);
    AtomType new_atom = addAtom(atom.atomicNumber(), atom.position3d());
    new_atom.setFormalCharge(atom.formalCharge());
    if (hasOccupancies)
      new_atom.setOccupancy(atom.occupancy());
    if (hasDisorder)
      new_atom.setDisorder(atom.disorderAssembly(), atom.disorderGroup());

    setAtomSelected(atomCount() - 1, true);
  }
  // now loop through and add the bonds
  for (size_t i = 0; i < mol.bondCount(); ++i) {
    Core::Bond bond = mol.bond(i);
    addBond(bond.atom1().index() + offset, bond.atom2().index() + offset,
            bond.order());
  }
  // now loop through and add the resiudes
  for (size_t i = 0; i < mol.residueCount(); ++i) {
    const Core::Residue& res = mol.residue(i);
    addResidue(res, offset);
  }
  endMergeMode();
  emitChanged(changes);
}

void RWMolecule::addResidue(const Core::Residue& residue, Index offset)
{
  // copy the residue name, chain, etc.
  std::string name = residue.residueName();
  Index id = residue.residueId();
  char chain = residue.chainId();
  m_molecule.addResidue(name, id, chain);
  Core::Residue& newResidue = m_molecule.residue(m_molecule.residueCount() - 1);
  newResidue.setHeterogen(residue.isHeterogen());
  newResidue.setSecondaryStructure(residue.secondaryStructure());

  // now go through all the atoms and add them using the offset
  for (Index atomIndex : residue.atomIndices()) {
    // get the new index
    Index newIndex = atomIndex + offset;
    Core::Atom myAtom = m_molecule.atom(newIndex);
    // get the atom name
    std::string atomName = residue.atomName(atomIndex);
    newResidue.addResidueAtom(atomName, myAtom);
  }
}

void RWMolecule::editUnitCell(Matrix3 cellMatrix, CrystalTools::Options options)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return;

  if (!UnitCell::isRegular(cellMatrix)) {
    qWarning() << "cell matrix is singular";
    return;
  }

  // Make a copy of the molecule to edit so we can store the old one
  // If the user has "TransformAtoms" set in the options, then
  // the atom positions will move as well.
  cancelBackgroundCalculations();
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

  // Wrapping clears and re-perceives the bonds, so edit a copy and let
  // modifyMolecule() store both states for undo.
  cancelBackgroundCalculations();
  Molecule newMolecule = m_molecule;

  CrystalTools::wrapAtomsToUnitCell(newMolecule);

  // Nothing moved and the bonds came out the same: no undo entry
  if (newMolecule.atomPositions3d() == m_molecule.atomPositions3d() &&
      newMolecule.bondPairs() == m_molecule.bondPairs() &&
      newMolecule.bondOrders() == m_molecule.bondOrders())
    return;

  Molecule::MoleculeChanges changes =
    Molecule::Atoms | Molecule::Bonds | Molecule::Modified;
  QString undoText = tr("Wrap Atoms to Cell");

  modifyMolecule(newMolecule, changes, undoText);
}

void RWMolecule::setCellVolume(double newVolume, CrystalTools::Options options)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return;

  // Make a copy of the molecule to edit so we can store the old one
  // The unit cell and atom positions may change
  cancelBackgroundCalculations();
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
  cancelBackgroundCalculations();
  Molecule newMolecule = m_molecule;

  CrystalTools::buildSupercell(newMolecule, a, b, c);

  // We will just modify the whole molecule since there may be many changes
  Molecule::MoleculeChanges changes =
    Molecule::UnitCell | Molecule::Modified | Molecule::Atoms | Molecule::Added;
  QString undoText = tr("Build Super Cell");

  modifyMolecule(newMolecule, changes, undoText);
}

void RWMolecule::buildSupercell(const Vector3& rangeMin,
                                const Vector3& rangeMax,
                                CrystalTools::Options options)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return;

  // Make a copy of the molecule to edit so we can store the old one
  // The unit cell and atom positions may change
  cancelBackgroundCalculations();
  Molecule newMolecule = m_molecule;

  if (!CrystalTools::buildSupercell(newMolecule, rangeMin, rangeMax, options))
    return;

  // We will just modify the whole molecule since there may be many changes
  Molecule::MoleculeChanges changes = Molecule::UnitCell | Molecule::Modified |
                                      Molecule::Atoms | Molecule::Bonds |
                                      Molecule::Added;
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
  cancelBackgroundCalculations();
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
  cancelBackgroundCalculations();
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

bool RWMolecule::reduceCellToPrimitive(double cartTol, double copyTol)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return false;

  // Make a copy of the molecule to edit so we can store the old one
  // The unit cell, atom positions, and numbers of atoms may change
  cancelBackgroundCalculations();
  Molecule newMolecule = m_molecule;
#ifdef USE_SPGLIB
  if (!Core::AvoSpglib::reduceToPrimitive(newMolecule, cartTol))
    return false;
#else
  return false;
#endif

  // Add boundary copies before committing, so it's a single undo step
  if (copyTol > 0.0)
    Core::SpaceGroups::fillTranslationalCopies(newMolecule, copyTol);

  // Since most components of the molecule will be modified,
  // we will just modify the whole thing...
  Molecule::MoleculeChanges changes =
    Molecule::UnitCell | Molecule::Atoms | Molecule::Added;
  QString undoText = tr("Reduce to Primitive");

  modifyMolecule(newMolecule, changes, undoText);

  // Resize layer info to match the new atom count
  Core::LayerManager::getMoleculeInfo(&m_molecule)
    ->layer.resize(m_molecule.atomCount());

  return true;
}

bool RWMolecule::conventionalizeCell(double cartTol, double copyTol)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return false;

  // Make a copy of the molecule to edit so we can store the old one
  // The unit cell, atom positions, and numbers of atoms may all change
  cancelBackgroundCalculations();
  Molecule newMolecule = m_molecule;

#ifdef USE_SPGLIB
  if (!Core::AvoSpglib::conventionalizeCell(newMolecule, cartTol))
    return false;
#else
  return false;
#endif

  // Add boundary copies before committing, so it's a single undo step
  if (copyTol > 0.0)
    Core::SpaceGroups::fillTranslationalCopies(newMolecule, copyTol);

  Molecule::MoleculeChanges changes =
    Molecule::UnitCell | Molecule::Atoms | Molecule::Added;
  QString undoText = tr("Conventionalize Cell");

  modifyMolecule(newMolecule, changes, undoText);

  // Resize layer info to match the new atom count
  Core::LayerManager::getMoleculeInfo(&m_molecule)
    ->layer.resize(m_molecule.atomCount());

  return true;
}

bool RWMolecule::symmetrizeCell(double cartTol, double copyTol)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return false;

  // Make a copy of the molecule to edit so we can store the old one
  // The unit cell, atom positions, and numbers of atoms may all change
  cancelBackgroundCalculations();
  Molecule newMolecule = m_molecule;

#ifdef USE_SPGLIB
  if (!Core::AvoSpglib::symmetrize(newMolecule, cartTol))
    return false;
#else
  return false;
#endif

  // Add boundary copies before committing, so it's a single undo step
  if (copyTol > 0.0)
    Core::SpaceGroups::fillTranslationalCopies(newMolecule, copyTol);

  Molecule::MoleculeChanges changes =
    Molecule::UnitCell | Molecule::Atoms | Molecule::Added;
  QString undoText = tr("Symmetrize Cell");

  modifyMolecule(newMolecule, changes, undoText);

  // Resize layer info to match the new atom count
  Core::LayerManager::getMoleculeInfo(&m_molecule)
    ->layer.resize(m_molecule.atomCount());

  return true;
}

bool RWMolecule::editUnitCell(const std::function<bool(Molecule&)>& edit,
                              Molecule::MoleculeChanges changes,
                              const QString& undoText, bool resizeLayers)
{
  // If there is no unit cell, there is nothing to do
  if (!m_molecule.unitCell())
    return false;

  // Make a copy of the molecule to edit so we can store the old one
  // The atom positions and numbers of atoms may change
  cancelBackgroundCalculations();
  Molecule newMolecule = m_molecule;

  if (!edit(newMolecule))
    return false;

  modifyMolecule(newMolecule, changes, undoText);

  if (resizeLayers) {
    // Resize layer info to match the new atom count
    Core::LayerManager::getMoleculeInfo(&m_molecule)
      ->layer.resize(m_molecule.atomCount());
  }
  return true;
}

bool RWMolecule::fillUnitCell(unsigned short hallNumber, double cartTol,
                              bool allCopies)
{
  return editUnitCell(
    [=](Molecule& mol) {
      mol.setHallNumber(hallNumber);
      Core::SpaceGroups::fillUnitCell(mol, hallNumber, cartTol, true,
                                      allCopies);
      return true;
    },
    Molecule::Added | Molecule::Atoms, tr("Fill Unit Cell"), false);
}

bool RWMolecule::fillUnitCellFromOperations(
  const std::vector<std::string>& operations, double cartTol, bool allCopies)
{
  // An empty list is not a symmetry; the core call would accept it
  if (operations.empty())
    return false;

  return editUnitCell(
    [&](Molecule& mol) {
      return Core::SpaceGroups::fillUnitCellFromOperations(
        mol, operations, cartTol, true, allCopies);
    },
    Molecule::Added | Molecule::Atoms, tr("Fill Unit Cell"), false);
}

bool RWMolecule::fillTranslationalCopies(double cartTol)
{
  if (!m_molecule.unitCell())
    return false;

  cancelBackgroundCalculations();
  Molecule newMolecule = m_molecule;

  Core::SpaceGroups::fillTranslationalCopies(newMolecule, cartTol);

  Molecule::MoleculeChanges changes = Molecule::Added | Molecule::Atoms;
  QString undoText = tr("Fill Translational Copies");

  modifyMolecule(newMolecule, changes, undoText);
  return true;
}

bool RWMolecule::reduceCellToAsymmetricUnit(unsigned short hallNumber,
                                            double cartTol)
{
  return editUnitCell(
    [=](Molecule& mol) {
      Core::SpaceGroups::reduceToAsymmetricUnit(mol, hallNumber, cartTol);
      return true;
    },
    Molecule::Removed | Molecule::Atoms, tr("Reduce Cell to Asymmetric Unit"),
    true);
}

bool RWMolecule::reduceCellToAsymmetricUnitFromOperations(
  const std::vector<std::string>& operations, double cartTol)
{
  // An empty list is not a symmetry; the core call would accept it
  if (operations.empty())
    return false;

  return editUnitCell(
    [&](Molecule& mol) {
      return Core::SpaceGroups::reduceToAsymmetricUnitFromOperations(
        mol, operations, cartTol);
    },
    Molecule::Removed | Molecule::Atoms, tr("Reduce Cell to Asymmetric Unit"),
    true);
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

} // namespace Avogadro::QtGui
