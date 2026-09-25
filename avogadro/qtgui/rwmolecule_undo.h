/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/
#ifndef AVOGADRO_QTGUI_RWMOLECULE_UNDO_H
#define AVOGADRO_QTGUI_RWMOLECULE_UNDO_H

#include "rwmolecule.h"

#include <QUndoCommand>
#include <cassert>

namespace Avogadro {
namespace QtGui {

using Core::Array;
using Core::AtomHybridization;
using Core::UnitCell;

// Base class for all undo commands used by this class.
// Used to expose molecule internals without needing to add explicit friendships
// between all undo commands and the container.
// Subclasses that want to support automatic merging should use the
// MergeUndoCommand interface below.
// Subclass implementations are inline in the code below. Specific undo
// operations are kept near the RWMolecule methods that use them.
class RWMolecule::UndoCommand : public QUndoCommand
{
public:
  UndoCommand(RWMolecule& m)
    : QUndoCommand(tr("Modify Molecule")), m_mol(m), m_molecule(m.m_molecule)
  {
  }

protected:
  Array<Vector3>& positions3d() { return m_molecule.atomPositions3d(); }
  Array<Index>& atomUniqueIds() { return m_mol.m_molecule.atomUniqueIds(); }
  Array<Index>& bondUniqueIds() { return m_mol.m_molecule.bondUniqueIds(); }
  // Selection has no public size accessor on Core::Molecule (unlike labels,
  // colors, etc., which expose their backing Array<T> directly): m_molecule
  // is protected, reached here only because UndoCommand is a nested class of
  // RWMolecule, which QtGui::Molecule befriends.
  bool hasSelectionEntry(Index atomId)
  {
    return atomId < m_molecule.m_selectedAtoms.size();
  }

  RWMolecule& m_mol;
  QtGui::Molecule& m_molecule;
};

namespace {
enum MergeIds
{
  SetPositions3dMergeId = 0,
  SetPosition3dMergeId,
  SetForceVectorMergeId,
  SetBondOrderMergeId,
  ModifySelectionMergeId,
  ModifyColorsMergeId
};

// Base class for undo commands that can be merged together, overriding the
// "after" state of an old command with that of the new command.
// Intended for use with RWMolecule's interactive mode.
// To add a new class, add a new entry to the MergeIds enum above and use that
// symbolic value as the template parameter. Implement the mergeWith() method
// to update the "after" state. See SetPositions3dCommand for an example.
template <int Id>
class MergeUndoCommand : public RWMolecule::UndoCommand
{
  bool m_canMerge;

public:
  MergeUndoCommand(RWMolecule& m) : UndoCommand(m), m_canMerge(false) {}
  void setCanMerge(bool merge) { m_canMerge = merge; }
  bool canMerge() const { return m_canMerge; }
  int id() const override { return m_canMerge ? Id : -1; }
};
} // namespace

namespace {
class AddAtomCommand : public RWMolecule::UndoCommand
{
  unsigned char m_atomicNumber;
  bool m_usingPositions;
  Index m_atomId;
  Index m_atomUid;
  size_t m_layer;
  bool m_added = false;

public:
  AddAtomCommand(RWMolecule& m, unsigned char aN, bool usingPositions,
                 Index atomId, Index uid)
    : UndoCommand(m), m_atomicNumber(aN), m_usingPositions(usingPositions),
      m_atomId(atomId), m_atomUid(uid)
  {
    m_layer = m_molecule.layer().activeLayer();
  }

  void redo() override
  {
    assert(m_molecule.atomCount() == m_atomId);
    auto atom =
      m_usingPositions
        ? m_molecule.addAtom(m_atomicNumber, Vector3::Zero(), m_atomUid)
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
    m_layer = m_molecule.layer().getLayerID(m_atomId);
    m_molecule.removeAtom(m_atomId);
  }
};
} // namespace

namespace {
class RemoveAtomCommand : public RWMolecule::UndoCommand
{
  Index m_atomId;
  Index m_atomUid;
  unsigned char m_atomicNumber;
  Vector3 m_position3d;
  Array<std::pair<Index, Index>> m_bonds;
  Array<unsigned char> m_orders;
  size_t m_layer;

  // Per-atom state captured just before removeAtom() in redo(), restored in
  // undo() once the atom is back at m_atomId. Each of these lives in an
  // Array that may be shorter than atomCount() -- an atom that was never
  // given one has no entry, and the accessor falls back to a default rather
  // than indexing out of bounds. The matching setter grows the array to
  // atomCount() on first write, though, so calling it unconditionally would
  // manufacture an entry (and, for color specifically, freeze what the
  // accessor otherwise computes fresh from the atomic number) for every atom
  // the growth covers, not just this one. So each field is only restored
  // when the removed atom actually had it.
  //
  // Calculated results (partial charges, force vectors, vibration data, ...)
  // are not restored: removeAtom() clears them for every atom, since they
  // describe a molecule that no longer exists once an atom is gone. Restoring
  // just this atom's would leave one real value among defaults.
  bool m_hasLabel = false;
  std::string m_label;
  bool m_hasSelection = false;
  bool m_selected = false;
  bool m_hasFormalCharge = false;
  signed char m_formalCharge = 0;
  bool m_hasColor = false;
  Vector3ub m_color = Vector3ub(0, 0, 0);
  bool m_hasIsotope = false;
  unsigned short m_isotope = 0;
  bool m_hasHybridization = false;
  AtomHybridization m_hybridization = Core::HybridizationUnknown;
  bool m_hasPosition2d = false;
  Vector2 m_position2d = Vector2::Zero();
  bool m_hasFrozen = false;
  bool m_frozenAxis[3] = { false, false, false };

public:
  RemoveAtomCommand(RWMolecule& m, Index atomId, Index uid, unsigned char aN,
                    const Vector3& pos)
    : UndoCommand(m), m_atomId(atomId), m_atomUid(uid), m_atomicNumber(aN),
      m_position3d(pos)
  {
  }

  void redo() override
  {
    assert(m_atomId < m_molecule.atomCount());
    m_layer = m_molecule.layer().getLayerID(m_atomId);
    m_bonds = m_molecule.getAtomBonds(m_atomId);
    m_orders = m_molecule.getAtomOrders(m_atomId);

    m_hasLabel = m_molecule.atomLabels().size() > m_atomId;
    if (m_hasLabel)
      m_label = m_molecule.atomLabel(m_atomId);

    m_hasSelection = hasSelectionEntry(m_atomId);
    if (m_hasSelection)
      m_selected = m_molecule.atomSelected(m_atomId);

    m_hasFormalCharge = m_molecule.formalCharges().size() > m_atomId;
    if (m_hasFormalCharge)
      m_formalCharge = m_molecule.formalCharge(m_atomId);

    m_hasColor = m_molecule.colors().size() > m_atomId;
    if (m_hasColor)
      m_color = m_molecule.color(m_atomId);

    m_hasIsotope = m_molecule.isotopes().size() > m_atomId;
    if (m_hasIsotope)
      m_isotope = m_molecule.isotope(m_atomId);

    m_hasHybridization = m_molecule.hybridizations().size() > m_atomId;
    if (m_hasHybridization)
      m_hybridization = m_molecule.hybridization(m_atomId);

    m_hasPosition2d = m_molecule.atomPositions2d().size() > m_atomId;
    if (m_hasPosition2d)
      m_position2d = m_molecule.atomPosition2d(m_atomId);

    // The frozen-atom mask grows in whole-atom (3-row) units, so an atom
    // either has all three axis entries or none.
    m_hasFrozen = m_molecule.frozenAtomMask().rows() >=
                  static_cast<Eigen::Index>(3 * (m_atomId + 1));
    if (m_hasFrozen) {
      for (int axis = 0; axis < 3; ++axis)
        m_frozenAxis[axis] = m_molecule.frozenAtomAxis(m_atomId, axis);
    }

    m_molecule.removeAtom(m_atomId);
  }

  void undo() override
  {
    // As in RemoveBondCommand::undo(): a refused add leaves atomCount()
    // unchanged, and everything below indexes with atomCount() - 1.
    auto atom = m_molecule.addAtom(m_atomicNumber, m_position3d, m_atomUid);
    if (!atom.isValid())
      return;

    // Swap the moved and unremoved atom data if needed
    Index movedId = m_mol.atomCount() - 1;
    m_molecule.layer().addAtom(m_layer, movedId);
    m_molecule.swapAtom(m_atomId, movedId);
    m_molecule.addBonds(m_bonds, m_orders);
    m_bonds.clear();

    // The atom is back at m_atomId now: restore whatever it had, and leave
    // everything else alone.
    if (m_hasLabel)
      m_molecule.setAtomLabel(m_atomId, m_label);
    if (m_hasSelection)
      m_molecule.setAtomSelected(m_atomId, m_selected);
    if (m_hasFormalCharge)
      m_molecule.setFormalCharge(m_atomId, m_formalCharge);
    if (m_hasColor)
      m_molecule.setColor(m_atomId, m_color);
    if (m_hasIsotope)
      m_molecule.setIsotope(m_atomId, m_isotope);
    if (m_hasHybridization)
      m_molecule.setHybridization(m_atomId, m_hybridization);
    if (m_hasPosition2d)
      m_molecule.setAtomPosition2d(m_atomId, m_position2d);
    if (m_hasFrozen) {
      for (int axis = 0; axis < 3; ++axis)
        m_molecule.setFrozenAtomAxis(m_atomId, axis, m_frozenAxis[axis]);
    }
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
class SetAtomicNumbersCommand : public RWMolecule::UndoCommand
{
  Core::Array<unsigned char> m_oldAtomicNumbers;
  Core::Array<unsigned char> m_newAtomicNumbers;

public:
  SetAtomicNumbersCommand(RWMolecule& m,
                          const Core::Array<unsigned char>& oldAtomicNumbers,
                          const Core::Array<unsigned char>& newAtomicNumbers)
    : UndoCommand(m), m_oldAtomicNumbers(oldAtomicNumbers),
      m_newAtomicNumbers(newAtomicNumbers)
  {
  }

  void redo() override { m_molecule.setAtomicNumbers(m_newAtomicNumbers); }

  void undo() override { m_molecule.setAtomicNumbers(m_oldAtomicNumbers); }
};
} // namespace

namespace {
class SetAtomicNumberCommand : public RWMolecule::UndoCommand
{
  Index m_atomId;
  unsigned char m_oldAtomicNumber;
  unsigned char m_newAtomicNumber;

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
    m_molecule.setAtomicNumber(m_atomId, m_newAtomicNumber);
  }

  void undo() override
  {
    m_molecule.setAtomicNumber(m_atomId, m_oldAtomicNumber);
  }
};
} // namespace

namespace {
class SetPositions3dCommand : public MergeUndoCommand<SetPositions3dMergeId>
{
  Core::Array<Vector3> m_oldPositions3d;
  Core::Array<Vector3> m_newPositions3d;

public:
  SetPositions3dCommand(RWMolecule& m,
                        const Core::Array<Vector3>& oldPositions3d,
                        const Core::Array<Vector3>& newPositions3d)
    : MergeUndoCommand<SetPositions3dMergeId>(m),
      m_oldPositions3d(oldPositions3d), m_newPositions3d(newPositions3d)
  {
  }

  void redo() override { positions3d() = m_newPositions3d; }

  void undo() override { positions3d() = m_oldPositions3d; }

  bool mergeWith(const QUndoCommand* other) override
  {
    const SetPositions3dCommand* o =
      dynamic_cast<const SetPositions3dCommand*>(other);
    if (o) {
      m_newPositions3d = o->m_newPositions3d;
      return true;
    }
    return false;
  }
};
} // namespace

namespace {
class SetPosition3dCommand : public MergeUndoCommand<SetPosition3dMergeId>
{
  Array<Index> m_atomIds;
  Array<Vector3> m_oldPosition3ds;
  Array<Vector3> m_newPosition3ds;

public:
  SetPosition3dCommand(RWMolecule& m, Index atomId,
                       const Vector3& oldPosition3d,
                       const Vector3& newPosition3d)
    : MergeUndoCommand<SetPosition3dMergeId>(m), m_atomIds(1, atomId),
      m_oldPosition3ds(1, oldPosition3d), m_newPosition3ds(1, newPosition3d)
  {
  }

  void redo() override
  {
    for (size_t i = 0; i < m_atomIds.size(); ++i)
      positions3d()[m_atomIds[i]] = m_newPosition3ds[i];
  }

  void undo() override
  {
    for (size_t i = 0; i < m_atomIds.size(); ++i)
      positions3d()[m_atomIds[i]] = m_oldPosition3ds[i];
  }

  bool mergeWith(const QUndoCommand* o) override
  {
    const SetPosition3dCommand* other =
      dynamic_cast<const SetPosition3dCommand*>(o);
    if (!other)
      return false;

    size_t numAtoms = other->m_atomIds.size();
    if (numAtoms != other->m_oldPosition3ds.size() ||
        numAtoms != other->m_newPosition3ds.size()) {
      return false;
    }

    for (size_t i = 0; i < numAtoms; ++i) {
      const Index& atomId = other->m_atomIds[i];
      const Vector3& oldPos = other->m_oldPosition3ds[i];
      const Vector3& newPos = other->m_newPosition3ds[i];

      Array<Index>::const_iterator idsBegin = m_atomIds.begin();
      Array<Index>::const_iterator idsEnd = m_atomIds.end();
      Array<Index>::const_iterator match = std::find(idsBegin, idsEnd, atomId);

      if (match == idsEnd) {
        // Append a new atom:
        m_atomIds.push_back(atomId);
        m_oldPosition3ds.push_back(oldPos);
        m_newPosition3ds.push_back(newPos);
      } else {
        // Overwrite the existing movement:
        size_t offset = std::distance(idsBegin, match);
        assert(m_atomIds[offset] == atomId);
        m_newPosition3ds[offset] = newPos;
      }
    }

    return true;
  }
};
} // namespace

namespace {
class SetAtomHybridizationCommand : public RWMolecule::UndoCommand
{
  Index m_atomId;
  AtomHybridization m_oldHybridization;
  AtomHybridization m_newHybridization;

public:
  SetAtomHybridizationCommand(RWMolecule& m, Index atomId,
                              AtomHybridization oldHybridization,
                              AtomHybridization newHybridization)
    : UndoCommand(m), m_atomId(atomId), m_oldHybridization(oldHybridization),
      m_newHybridization(newHybridization)
  {
  }

  void redo() override
  {
    m_molecule.setHybridization(m_atomId, m_newHybridization);
  }

  void undo() override
  {
    m_molecule.setHybridization(m_atomId, m_oldHybridization);
  }
};
} // namespace

namespace {
class SetAtomFormalChargeCommand : public RWMolecule::UndoCommand
{
  Index m_atomId;
  signed char m_oldCharge;
  signed char m_newCharge;

public:
  SetAtomFormalChargeCommand(RWMolecule& m, Index atomId, signed char oldCharge,
                             signed char newCharge)
    : UndoCommand(m), m_atomId(atomId), m_oldCharge(oldCharge),
      m_newCharge(newCharge)
  {
  }

  void redo() override { m_molecule.setFormalCharge(m_atomId, m_newCharge); }

  void undo() override { m_molecule.setFormalCharge(m_atomId, m_oldCharge); }
};
} // namespace

namespace {
class SetAtomColorCommand : public RWMolecule::UndoCommand
{
  Index m_atomId;
  Vector3ub m_oldColor;
  Vector3ub m_newColor;

public:
  SetAtomColorCommand(RWMolecule& m, Index atomId, Vector3ub oldColor,
                      Vector3ub newColor)
    : UndoCommand(m), m_atomId(atomId), m_oldColor(oldColor),
      m_newColor(newColor)
  {
  }

  void redo() override { m_molecule.setColor(m_atomId, m_newColor); }

  void undo() override { m_molecule.setColor(m_atomId, m_oldColor); }
};

class SetResidueColorCommand : public RWMolecule::UndoCommand
{
  Index m_residueId;
  Vector3ub m_oldColor;
  Vector3ub m_newColor;

public:
  SetResidueColorCommand(RWMolecule& m, Index residueId, Vector3ub oldColor,
                         Vector3ub newColor)
    : UndoCommand(m), m_residueId(residueId), m_oldColor(oldColor),
      m_newColor(newColor)
  {
  }

  void redo() override { m_molecule.residue(m_residueId).setColor(m_newColor); }

  void undo() override { m_molecule.residue(m_residueId).setColor(m_oldColor); }
};

class SetLayerCommand : public RWMolecule::UndoCommand
{
  Index m_atomId;
  size_t m_oldLayer;
  size_t m_newLayer;

public:
  SetLayerCommand(RWMolecule& m, Index atomId, size_t oldLayer, size_t newLayer)
    : UndoCommand(m), m_atomId(atomId), m_oldLayer(oldLayer),
      m_newLayer(newLayer)
  {
  }

  void redo() override { m_molecule.setLayer(m_atomId, m_newLayer); }

  void undo() override { m_molecule.setLayer(m_atomId, m_oldLayer); }
};

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
class RemoveBondCommand : public RWMolecule::UndoCommand
{
  Index m_bondId;
  Index m_bondUid;
  std::pair<Index, Index> m_bondPair;
  unsigned char m_bondOrder;

public:
  RemoveBondCommand(RWMolecule& m, Index bondId, Index bondUid,
                    const std::pair<Index, Index>& bondPair,
                    unsigned char bondOrder)
    : UndoCommand(m), m_bondId(bondId), m_bondUid(bondUid),
      m_bondPair(bondPair), m_bondOrder(bondOrder)
  {
  }

  void redo() override { m_molecule.removeBond(m_bondId); }

  void undo() override
  {
    // The bond may not come back: addBond() refuses a unique id that is no
    // longer free and atom indices that no longer exist. bondCount() has not
    // grown then, so the swap below would name a bond that is not there --
    // and on an empty molecule bondCount() - 1 underflows to MaxIndex.
    auto bond = m_molecule.addBond(m_bondPair.first, m_bondPair.second,
                                   m_bondOrder, m_bondUid);
    if (!bond.isValid())
      return;

    Index movedId = m_molecule.bondCount() - 1;
    m_molecule.swapBond(m_bondId, movedId);
  }
};
} // namespace

namespace {
class SetBondOrdersCommand : public RWMolecule::UndoCommand
{
  Array<unsigned char> m_oldBondOrders;
  Array<unsigned char> m_newBondOrders;

public:
  SetBondOrdersCommand(RWMolecule& m, const Array<unsigned char>& oldBondOrders,
                       const Array<unsigned char>& newBondOrders)
    : UndoCommand(m), m_oldBondOrders(oldBondOrders),
      m_newBondOrders(newBondOrders)
  {
  }

  void redo() override { m_molecule.setBondOrders(m_newBondOrders); }

  void undo() override { m_molecule.setBondOrders(m_oldBondOrders); }
};
} // namespace

namespace {
class SetBondOrderCommand : public MergeUndoCommand<SetBondOrderMergeId>
{
  Index m_bondId;
  unsigned char m_oldBondOrder;
  unsigned char m_newBondOrder;

public:
  SetBondOrderCommand(RWMolecule& m, Index bondId, unsigned char oldBondOrder,
                      unsigned char newBondOrder)
    : MergeUndoCommand<SetBondOrderMergeId>(m), m_bondId(bondId),
      m_oldBondOrder(oldBondOrder), m_newBondOrder(newBondOrder)
  {
  }

  void redo() override { m_molecule.setBondOrder(m_bondId, m_newBondOrder); }

  void undo() override { m_molecule.setBondOrder(m_bondId, m_oldBondOrder); }

  bool mergeWith(const QUndoCommand* other) override
  {
    const SetBondOrderCommand* o =
      dynamic_cast<const SetBondOrderCommand*>(other);
    // Only merge when the bondIds match.
    if (o && o->m_bondId == this->m_bondId) {
      this->m_newBondOrder = o->m_newBondOrder;
      return true;
    }
    return false;
  }
};
} // namespace

namespace {
class SetBondPairsCommand : public RWMolecule::UndoCommand
{
  Array<std::pair<Index, Index>> m_oldBondPairs;
  Array<std::pair<Index, Index>> m_newBondPairs;

public:
  SetBondPairsCommand(RWMolecule& m,
                      const Array<std::pair<Index, Index>>& oldBondPairs,
                      const Array<std::pair<Index, Index>>& newBondPairs)
    : UndoCommand(m), m_oldBondPairs(oldBondPairs), m_newBondPairs(newBondPairs)
  {
  }

  void redo() override { m_molecule.setBondPairs(m_newBondPairs); }

  void undo() override { m_molecule.setBondPairs(m_oldBondPairs); }
};
} // namespace

namespace {
class SetBondPairCommand : public RWMolecule::UndoCommand
{
  Index m_bondId;
  std::pair<Index, Index> m_oldBondPair;
  std::pair<Index, Index> m_newBondPair;

public:
  SetBondPairCommand(RWMolecule& m, Index bondId,
                     const std::pair<Index, Index>& oldBondPair,
                     const std::pair<Index, Index>& newBondPair)
    : UndoCommand(m), m_bondId(bondId), m_oldBondPair(oldBondPair),
      m_newBondPair(newBondPair)
  {
  }

  void redo() override { m_molecule.setBondPair(m_bondId, m_newBondPair); }

  void undo() override { m_molecule.setBondPair(m_bondId, m_oldBondPair); }
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
    : UndoCommand(m), m_oldMolecule(oldMolecule), m_newMolecule(newMolecule)
  {
  }

  void redo() override { m_mol.molecule() = m_newMolecule; }

  void undo() override { m_mol.molecule() = m_oldMolecule; }
};
} // namespace

namespace {
class SetForceVectorCommand : public MergeUndoCommand<SetForceVectorMergeId>
{
  Array<Index> m_atomIds;
  Array<Vector3> m_oldForceVectors;
  Array<Vector3> m_newForceVectors;

public:
  SetForceVectorCommand(RWMolecule& m, Index atomId,
                        const Vector3& oldForceVector,
                        const Vector3& newForceVector)
    : MergeUndoCommand<SetForceVectorMergeId>(m), m_atomIds(1, atomId),
      m_oldForceVectors(1, oldForceVector), m_newForceVectors(1, newForceVector)
  {
  }

  void redo() override
  {
    for (size_t i = 0; i < m_atomIds.size(); ++i)
      m_molecule.setForceVector(m_atomIds[i], m_newForceVectors[i]);
  }

  void undo() override
  {
    for (size_t i = 0; i < m_atomIds.size(); ++i)
      m_molecule.setForceVector(m_atomIds[i], m_oldForceVectors[i]);
  }

  bool mergeWith(const QUndoCommand* o) override
  {
    const SetForceVectorCommand* other =
      dynamic_cast<const SetForceVectorCommand*>(o);
    if (!other)
      return false;

    size_t numAtoms = other->m_atomIds.size();
    if (numAtoms != other->m_oldForceVectors.size() ||
        numAtoms != other->m_newForceVectors.size()) {
      return false;
    }

    for (size_t i = 0; i < numAtoms; ++i) {
      const Index& atomId = other->m_atomIds[i];
      const Vector3& oldPos = other->m_oldForceVectors[i];
      const Vector3& newPos = other->m_newForceVectors[i];

      Array<Index>::const_iterator idsBegin = m_atomIds.begin();
      Array<Index>::const_iterator idsEnd = m_atomIds.end();
      Array<Index>::const_iterator match = std::find(idsBegin, idsEnd, atomId);

      if (match == idsEnd) {
        // Append a new atom:
        m_atomIds.push_back(atomId);
        m_oldForceVectors.push_back(oldPos);
        m_newForceVectors.push_back(newPos);
      } else {
        // Overwrite the existing movement:
        size_t offset = std::distance(idsBegin, match);
        assert(m_atomIds[offset] == atomId);
        m_newForceVectors[offset] = newPos;
      }
    }

    return true;
  }
};
} // namespace

namespace {
class ModifyAtomLabelCommand : public RWMolecule::UndoCommand
{
  Index m_atomId;
  std::string m_newLabel;
  std::string m_oldLabel;

public:
  ModifyAtomLabelCommand(RWMolecule& m, Index atomId, const std::string& label)
    : UndoCommand(m), m_atomId(atomId), m_newLabel(label)
  {
    m_oldLabel = m_mol.molecule().atomLabel(m_atomId);
  }

  void redo() override { m_mol.molecule().setAtomLabel(m_atomId, m_newLabel); }

  void undo() override { m_mol.molecule().setAtomLabel(m_atomId, m_oldLabel); }
};
} // namespace

namespace {
class ModifyBondLabelCommand : public RWMolecule::UndoCommand
{
  Index m_bondId;
  std::string m_newLabel;
  std::string m_oldLabel;

public:
  ModifyBondLabelCommand(RWMolecule& m, Index bondId, const std::string& label)
    : UndoCommand(m), m_bondId(bondId), m_newLabel(label)
  {
    m_oldLabel = m_mol.molecule().bondLabel(m_bondId);
  }

  void redo() override { m_mol.molecule().setBondLabel(m_bondId, m_newLabel); }

  void undo() override { m_mol.molecule().setBondLabel(m_bondId, m_oldLabel); }
};
} // namespace

namespace {
class ModifySelectionCommand : public MergeUndoCommand<ModifySelectionMergeId>
{
  std::vector<bool> m_newSelectedAtoms;
  std::vector<bool> m_oldSelectedAtoms;

public:
  ModifySelectionCommand(RWMolecule& m, Index atomId, bool selected)
    : MergeUndoCommand<ModifySelectionMergeId>(m)
  {
    Index atomCount = m_mol.molecule().atomCount();
    m_oldSelectedAtoms.resize(atomCount);
    m_newSelectedAtoms.resize(atomCount);

    for (Index i = 0; i < atomCount; ++i) {
      m_oldSelectedAtoms[i] = m_molecule.atomSelected(i);
      m_newSelectedAtoms[i] = m_molecule.atomSelected(i);
    }

    // Guarded here as well as at the call, since these vectors are sized to
    // the atom count and operator[] on std::vector<bool> writes into a word
    // computed from the index -- an out-of-range one lands somewhere else
    // entirely.
    if (atomId < atomCount)
      m_newSelectedAtoms[atomId] = selected;
  }

  void redo() override
  {
    Index atomCount = m_mol.molecule().atomCount();
    for (Index i = 0; i < atomCount; ++i)
      m_mol.molecule().setAtomSelected(i, m_newSelectedAtoms[i]);
  }

  void undo() override
  {
    Index atomCount = m_mol.molecule().atomCount();
    for (Index i = 0; i < atomCount; ++i)
      m_mol.molecule().setAtomSelected(i, m_oldSelectedAtoms[i]);
  }

  bool mergeWith(const QUndoCommand* other) override
  {
    const ModifySelectionCommand* o =
      dynamic_cast<const ModifySelectionCommand*>(other);
    if (!o)
      return false;

    // check if the atom count matches
    Index numAtoms = m_oldSelectedAtoms.size();

    if (numAtoms != o->m_oldSelectedAtoms.size() ||
        numAtoms != o->m_newSelectedAtoms.size())
      return false;

    // merge these, by grabbing the new selected atoms
    m_newSelectedAtoms = o->m_newSelectedAtoms;
    return true;
  }
};
} // namespace

/*
namespace {
class ModifyColorCommand : public MergeUndoCommand<ModifyColorMergeId>
{
  Array<Vector3ub> m_newSelectedAtoms;
  Array<Vector3ub> m_oldSelectedAtoms;

public:
  ModifySelectionCommand(RWMolecule& m, Index atomId, bool selected)
    : MergeUndoCommand<ModifySelectionMergeId>(m)
  {
    Index atomCount = m_mol.molecule().atomCount();
    m_oldSelectedAtoms.reserve(atomCount);
    m_newSelectedAtoms.reserve(atomCount);

    for (Index i = 0; i < atomCount; ++i) {
      m_oldSelectedAtoms[i] = m_molecule.atomSelected(i);
      m_newSelectedAtoms[i] = m_molecule.atomSelected(i);
    }

    m_newSelectedAtoms[atomId] = selected;
  }

  void redo() override
  {
    Index atomCount = m_mol.molecule().atomCount();
    for (Index i = 0; i < atomCount; ++i)
      m_mol.molecule().setAtomSelected(i, m_newSelectedAtoms[i]);
  }

  void undo() override
  {
    Index atomCount = m_mol.molecule().atomCount();
    for (Index i = 0; i < atomCount; ++i)
      m_mol.molecule().setAtomSelected(i, m_oldSelectedAtoms[i]);
  }

  bool mergeWith(const QUndoCommand* other) override
  {
    const ModifySelectionCommand* o =
      dynamic_cast<const ModifySelectionCommand*>(other);
    if (o) {
      // check if the atom count matches
      Index numAtoms = m_oldSelectedAtoms.size();
      if (numAtoms != o->m_oldSelectedAtoms.size() ||
          numAtoms != o->m_newSelectedAtoms.size()) {
        return false;
      }

      // merge these, by grabbing the new selected atoms
      for (Index i = 0; i < numAtoms; ++i)
        m_newSelectedAtoms[i] = o->m_newSelectedAtoms[i];

      return true;
    }
    return false;
  }
};
} // namespace
*/

} // namespace QtGui
} // namespace Avogadro
#endif
