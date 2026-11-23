/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/
#ifndef AVOGADRO_QTGUI_RWMOLECULE_UNDO_H
#define AVOGADRO_QTGUI_RWMOLECULE_UNDO_H

#include "rwmolecule.h"

#include <QUndoCommand>

#include <algorithm>
#include <cassert>
#include <utility>
#include <vector>

namespace Avogadro::QtGui {

using Core::Array;
using Core::UnitCell;

// Base class for all undo commands used by this class.
// Used to expose molecule internals without needing to add explicit friendships
// between all undo commands and the container.
// Most commands just set a value, an array or some entries through a setter and
// are the templates below. They merge when given a merge id (see MergeIds).
// Subclass implementations are inline in the code below. Specific undo
// operations are kept near the RWMolecule methods that use them.
class RWMolecule::UndoCommand : public QUndoCommand
{
public:
  UndoCommand(RWMolecule& m)
    : QUndoCommand(tr("Modify Molecule")), m_mol(m), m_molecule(m.m_molecule)
  {
  }

  // Consecutive commands with the same merge id (see MergeIds) are offered to
  // mergeWith(). The default, -1, never merges.
  void setMergeId(int mergeId) { m_mergeId = mergeId; }
  int id() const override { return m_mergeId; }

protected:
  Array<Index>& bondUniqueIds() { return m_mol.m_molecule.bondUniqueIds(); }

  RWMolecule& m_mol;
  QtGui::Molecule& m_molecule;

private:
  int m_mergeId = -1;
};

namespace {
// Ids that let QUndoStack merge consecutive commands of one kind. A command
// that does not merge has the id -1. To add one, add an entry here and give it
// to the command with setMergeId().
enum MergeIds
{
  SetPositions3dMergeId = 0,
  SetPosition3dMergeId,
  SetBondOrderMergeId,
  ModifySelectionMergeId
};
} // namespace

namespace {
// Sets one entry (an atom, bond or residue) of a molecule through a setter.
// The old and new values are read by the caller. With a merge id set,
// consecutive commands on the same entry (and the same setter) merge: the
// merged command keeps the first old value and takes the last new value.
template <typename T>
class SetEntryCommand : public RWMolecule::UndoCommand
{
public:
  using Setter = void (*)(Molecule&, Index, const T&);

  SetEntryCommand(RWMolecule& m, Setter setter, Index index, T oldValue,
                  T newValue)
    : UndoCommand(m), m_setter(setter), m_index(index),
      m_old(std::move(oldValue)), m_new(std::move(newValue))
  {
  }

  void redo() override { m_setter(m_molecule, m_index, m_new); }
  void undo() override { m_setter(m_molecule, m_index, m_old); }

  bool mergeWith(const QUndoCommand* other) override
  {
    const auto* o = dynamic_cast<const SetEntryCommand<T>*>(other);
    if (o == nullptr || o->m_setter != m_setter || o->m_index != m_index)
      return false;

    m_new = o->m_new;
    return true;
  }

private:
  Setter m_setter;
  Index m_index;
  T m_old;
  T m_new;
};

// Sets a whole array of a molecule through a setter. With a merge id set,
// consecutive commands with the same setter merge: the merged command keeps
// the first old array and takes the last new one.
template <typename T>
class SetArrayCommand : public RWMolecule::UndoCommand
{
public:
  using Setter = void (*)(Molecule&, const Array<T>&);

  SetArrayCommand(RWMolecule& m, Setter setter, const Array<T>& oldValues,
                  const Array<T>& newValues)
    : UndoCommand(m), m_setter(setter), m_old(oldValues), m_new(newValues)
  {
  }

  void redo() override { m_setter(m_molecule, m_new); }
  void undo() override { m_setter(m_molecule, m_old); }

  bool mergeWith(const QUndoCommand* other) override
  {
    const auto* o = dynamic_cast<const SetArrayCommand<T>*>(other);
    if (o == nullptr || o->m_setter != m_setter)
      return false;

    // Share the other command's array (QUndoStack deletes it next) rather
    // than deep-copying it, as Array's copy assignment would.
    Array<T> shared(o->m_new);
    m_new.swap(shared);
    return true;
  }

private:
  Setter m_setter;
  Array<T> m_old;
  Array<T> m_new;
};

// Sets some entries of a molecule's atoms through a setter, and stores only
// those entries. Merging adds the other command's entries: one already held
// keeps its old value and takes the other's new value. The entries are kept
// sorted by index, so a sweep over the atoms in ascending order appends. A
// command only merges with one made for the same number of atoms.
template <typename T>
class SetEntriesCommand : public RWMolecule::UndoCommand
{
public:
  using Setter = void (*)(Molecule&, Index, const T&);

  SetEntriesCommand(RWMolecule& m, Setter setter, Index index,
                    const T& oldValue, const T& newValue)
    : UndoCommand(m), m_setter(setter), m_atomCount(m_molecule.atomCount()),
      m_ids(1, index), m_old(1, oldValue), m_new(1, newValue)
  {
  }

  void redo() override { apply(m_new); }
  void undo() override { apply(m_old); }

  bool mergeWith(const QUndoCommand* other) override
  {
    const auto* o = dynamic_cast<const SetEntriesCommand<T>*>(other);
    if (o == nullptr || o->m_setter != m_setter ||
        o->m_atomCount != m_atomCount)
      return false;

    for (size_t i = 0; i < o->m_ids.size(); ++i) {
      auto it = std::lower_bound(m_ids.begin(), m_ids.end(), o->m_ids[i]);
      const auto offset = it - m_ids.begin();
      if (it != m_ids.end() && *it == o->m_ids[i]) {
        // Overwrite the existing entry's new value.
        m_new[offset] = o->m_new[i];
      } else {
        m_ids.insert(it, o->m_ids[i]);
        m_old.insert(m_old.begin() + offset, o->m_old[i]);
        m_new.insert(m_new.begin() + offset, o->m_new[i]);
      }
    }
    return true;
  }

private:
  void apply(const std::vector<T>& values)
  {
    for (size_t i = 0; i < m_ids.size(); ++i)
      m_setter(m_molecule, m_ids[i], values[i]);
  }

  Setter m_setter;
  Index m_atomCount;
  std::vector<Index> m_ids; // sorted, ascending
  std::vector<T> m_old;
  std::vector<T> m_new;
};
} // namespace

namespace {
// Undoing the add of an atom removes it, and redoing puts back exactly what
// was removed: the atom with everything that was done to it since, taken as a
// snapshot (R4). Later commands are undone first, so the atom has no bonds.
class AddAtomCommand : public RWMolecule::UndoCommand
{
  unsigned char m_atomicNumber;
  bool m_usingPositions;
  Index m_atomId;
  Index m_atomUid;
  size_t m_layer;
  bool m_added = false;
  Vector3 m_position3d;
  Core::AtomSnapshot m_snapshot; // empty until the first undo

public:
  AddAtomCommand(RWMolecule& m, unsigned char aN, bool usingPositions,
                 Index atomId, Index uid,
                 const Vector3& position3d = Vector3::Zero())
    : UndoCommand(m), m_atomicNumber(aN), m_usingPositions(usingPositions),
      m_atomId(atomId), m_atomUid(uid), m_position3d(position3d)
  {
    m_layer = m_molecule.layer().activeLayer();
  }

  void redo() override
  {
    assert(m_molecule.atomCount() == m_atomId);
    if (!m_snapshot.isEmpty()) {
      // A redo after an undo. An atom that cannot go back leaves the molecule
      // as it was, and undoing that must do the same.
      m_added = m_molecule.restoreAtomSnapshot(m_atomId, m_snapshot, m_atomUid);
      return;
    }

    auto atom = m_usingPositions
                  ? m_molecule.addAtom(m_atomicNumber, m_position3d, m_atomUid)
                  : m_molecule.addAtom(m_atomicNumber, m_atomUid);
    // An add that was refused leaves the molecule as it was, and undoing it
    // must do the same -- removing m_atomId then takes whichever atom has
    // since come to sit at that index.
    m_added = atom.isValid();
    if (!m_added)
      return;

    m_molecule.layer().addAtom(m_layer, m_atomId);
  }

  void undo() override
  {
    if (!m_added)
      return;

    assert(m_molecule.atomCount() == m_atomId + 1);
    m_snapshot = m_molecule.atomSnapshot(m_atomId);
    m_molecule.removeAtom(m_atomId);
  }
};
} // namespace

namespace {
// The snapshot holds everything removeAtom() discards that undo restores
// (R4): the atom's state in every array and coordinate set, the layer, and the
// constraints, scan coordinates and residues that named it. RWMolecule removes
// the atom's bonds with commands of their own first. Calculated results are
// not restored (R3).
class RemoveAtomCommand : public RWMolecule::UndoCommand
{
  Index m_atomId;
  Index m_atomUid;
  Core::AtomSnapshot m_snapshot;

public:
  RemoveAtomCommand(RWMolecule& m, Index atomId, Index uid)
    : UndoCommand(m), m_atomId(atomId), m_atomUid(uid)
  {
  }

  void redo() override
  {
    assert(m_atomId < m_molecule.atomCount());
    m_snapshot = m_molecule.atomSnapshot(m_atomId);
    m_molecule.removeAtom(m_atomId);
  }

  void undo() override
  {
    // As in RemoveBondCommand::undo(): the atom may not come back, if its
    // unique id is no longer free, and the molecule is then left as it was.
    m_molecule.restoreAtomSnapshot(m_atomId, m_snapshot, m_atomUid);
  }
};
} // namespace

namespace {
// Renumbering is stored as the sequence of transpositions that realises the
// permutation rather than as the permutation itself. A transposition is its
// own inverse, so undoing is the same sequence walked backwards, and there is
// no second permutation to keep consistent with the first.
//
// Unlike the other commands in this file, this one notifies directly instead
// of relying on the blanket Atoms | Added that MainWindow emits after an
// undo/redo: a reorder changes no atom or bond counts, so that blanket flag
// gives listeners (e.g. PropertyModel) nothing to detect the change by.
class ReorderAtomsCommand : public RWMolecule::UndoCommand
{
  std::vector<std::pair<Index, Index>> m_swaps;

public:
  ReorderAtomsCommand(RWMolecule& m,
                      const std::vector<std::pair<Index, Index>>& swaps)
    : UndoCommand(m), m_swaps(swaps)
  {
  }

  void redo() override
  {
    for (const auto& swap : m_swaps)
      m_molecule.swapAtom(swap.first, swap.second);
    m_molecule.emitChanged(Molecule::Atoms | Molecule::Bonds |
                           Molecule::Modified | Molecule::Reordered);
  }

  void undo() override
  {
    for (auto it = m_swaps.rbegin(); it != m_swaps.rend(); ++it)
      m_molecule.swapAtom(it->first, it->second);
    m_molecule.emitChanged(Molecule::Atoms | Molecule::Bonds |
                           Molecule::Modified | Molecule::Reordered);
  }
};
} // namespace

namespace {
class SetAtomicNumberCommand : public RWMolecule::UndoCommand
{
  Index m_atomId;
  unsigned char m_oldAtomicNumber;
  unsigned char m_newAtomicNumber;
  // Changing the element resets the atom's colour to the new element's, so
  // a colour the user chose has to be put back by undo. As in
  // RemoveAtomCommand, only an atom that had one is given one.
  bool m_hasColor = false;
  Vector3ub m_color = Vector3ub(0, 0, 0);

public:
  SetAtomicNumberCommand(RWMolecule& m, Index atomId,
                         unsigned char oldAtomicNumber,
                         unsigned char newAtomicNumber)
    : UndoCommand(m), m_atomId(atomId), m_oldAtomicNumber(oldAtomicNumber),
      m_newAtomicNumber(newAtomicNumber)
  {
  }

  void redo() override
  {
    m_hasColor = m_molecule.colors().size() > m_atomId;
    if (m_hasColor)
      m_color = m_molecule.color(m_atomId);
    m_molecule.setAtomicNumber(m_atomId, m_newAtomicNumber);
  }

  void undo() override
  {
    m_molecule.setAtomicNumber(m_atomId, m_oldAtomicNumber);
    if (m_hasColor)
      m_molecule.setColor(m_atomId, m_color);
  }
};
} // namespace

namespace {

class AddBondCommand : public RWMolecule::UndoCommand
{
  unsigned char m_bondOrder;
  std::pair<Index, Index> m_bondPair;
  Index m_bondId;
  Index m_bondUid;
  bool m_added = false;

public:
  AddBondCommand(RWMolecule& m, unsigned char order,
                 const std::pair<Index, Index>& bondPair, Index bondId,
                 Index uid)
    : UndoCommand(m), m_bondOrder(order), m_bondPair(bondPair),
      m_bondId(bondId), m_bondUid(uid)
  {
  }

  void redo() override
  {
    assert(m_molecule.bondCount() == m_bondId);
    const Index before = m_molecule.bondCount();

    // The bond has to come back under the unique id it had. On the first run
    // that id does not exist yet and the plain overload appends exactly it;
    // on a redo after an undo the slot is still there, tombstoned, and the
    // unique-id overload reclaims it. Appending a fresh id instead left every
    // PersistentBond pointing at the old one dangling and grew
    // m_bondUniqueIds by one on every undo/redo cycle.
    auto bond =
      (m_bondUid == static_cast<Index>(bondUniqueIds().size()))
        ? m_molecule.addBond(m_bondPair.first, m_bondPair.second, m_bondOrder)
        : m_molecule.addBond(m_bondPair.first, m_bondPair.second, m_bondOrder,
                             m_bondUid);

    // As in AddAtomCommand: undoing an add that never happened would remove
    // a bond this command does not own.
    m_added = bond.isValid() && m_molecule.bondCount() > before;
  }

  void undo() override
  {
    if (!m_added)
      return;

    // we know this is the top so just a simple remove
    m_molecule.removeBond(m_bondId);
  }
};
} // namespace

namespace {
// The snapshot holds the bond's atoms and its state: order, label and custom
// properties (R4).
class RemoveBondCommand : public RWMolecule::UndoCommand
{
  Index m_bondId;
  Index m_bondUid;
  Core::BondSnapshot m_snapshot;

public:
  RemoveBondCommand(RWMolecule& m, Index bondId, Index bondUid)
    : UndoCommand(m), m_bondId(bondId), m_bondUid(bondUid)
  {
  }

  void redo() override
  {
    m_snapshot = m_molecule.bondSnapshot(m_bondId);
    m_molecule.removeBond(m_bondId);
  }

  void undo() override
  {
    // The bond may not come back: its unique id may no longer be free, or its
    // atoms gone. The molecule is then left as it was.
    m_molecule.restoreBondSnapshot(m_bondId, m_snapshot, m_bondUid);
  }
};
} // namespace

namespace {
class AddUnitCellCommand : public RWMolecule::UndoCommand
{
  UnitCell m_newUnitCell;

public:
  AddUnitCellCommand(RWMolecule& m, const UnitCell& newUnitCell)
    : UndoCommand(m), m_newUnitCell(newUnitCell)
  {
  }

  void redo() override
  {
    m_mol.molecule().setUnitCell(new UnitCell(m_newUnitCell));
  }

  void undo() override { m_mol.molecule().setUnitCell(nullptr); }
};
} // namespace

namespace {
class RemoveUnitCellCommand : public RWMolecule::UndoCommand
{
  UnitCell m_oldUnitCell;

public:
  RemoveUnitCellCommand(RWMolecule& m, const UnitCell& oldUnitCell)
    : UndoCommand(m), m_oldUnitCell(oldUnitCell)
  {
  }

  void redo() override { m_mol.molecule().setUnitCell(nullptr); }

  void undo() override
  {
    m_mol.molecule().setUnitCell(new UnitCell(m_oldUnitCell));
  }
};
} // namespace

namespace {
class ModifyMoleculeCommand : public RWMolecule::UndoCommand
{
  Molecule m_oldMolecule;
  Molecule m_newMolecule;

public:
  ModifyMoleculeCommand(RWMolecule& m, const Molecule& oldMolecule,
                        const Molecule& newMolecule)
    : UndoCommand(m), m_newMolecule(newMolecule)
  {
    // The old molecule is the live one, and the undo commands pushed before
    // this one refer to its atoms and bonds by unique id. Molecule's copy
    // constructor renumbers the ids 0..n-1, which would make those commands
    // hit the wrong atom (or an id already taken) once deletions have left
    // holes in the tables. operator= copies the tables, so use it.
    m_oldMolecule = oldMolecule;

    // The new molecule is deliberately built with the copy constructor: it is
    // an edited copy, and Core-level edits (CrystalTools re-perceiving bonds,
    // building a supercell) change its atoms and bonds without touching the
    // QtGui id tables, so those may be stale. The renumbering makes them
    // consistent with its actual atom and bond counts.
  }

  // Assigning a molecule frees the basis set and cubes it replaces, which an
  // orbital or surface calculation may still be reading or writing.
  void redo() override
  {
    RWMolecule::cancelBackgroundCalculations();
    m_mol.molecule() = m_newMolecule;
  }

  void undo() override
  {
    RWMolecule::cancelBackgroundCalculations();
    m_mol.molecule() = m_oldMolecule;
  }
};
} // namespace

} // namespace Avogadro::QtGui

#endif
