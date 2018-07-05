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

#include <QtWidgets/QUndoCommand>

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
    : QUndoCommand(tr("Modify Molecule"))
    , m_mol(m)
  {}

protected:
  Array<Index>& atomUniqueIds() { return m_mol.m_molecule.atomUniqueIds(); }
  Array<Index>& bondUniqueIds() { return m_mol.m_molecule.bondUniqueIds(); }
  Array<unsigned char>& atomicNumbers()
  {
    return m_mol.m_molecule.atomicNumbers();
  }
  Array<Vector3>& positions3d() { return m_mol.m_molecule.atomPositions3d(); }
  Array<AtomHybridization>& hybridizations()
  {
    return m_mol.m_molecule.hybridizations();
  }
  Array<signed char>& formalCharges()
  {
    return m_mol.m_molecule.formalCharges();
  }
  Array<std::pair<Index, Index>>& bondPairs()
  {
    return m_mol.m_molecule.bondPairs();
  }
  Array<unsigned char>& bondOrders() { return m_mol.m_molecule.bondOrders(); }
  RWMolecule& m_mol;
};

namespace {
enum MergeIds
{
  SetPositions3dMergeId = 0,
  SetPosition3dMergeId,
  SetBondOrderMergeId
};

// Base class for undo commands that can be merged together, overridding the
// "after" state of an old command with that of the new command.
// Intended for use with RWMolecule's interactive mode.
// To add a new class, add a new entry to the MergeIds enum above and use that
// symbolic value as the template parameter. Implement the mergeWith() method
// to update the "after" state. See SetPositions3dCommand for an example.
template<int Id>
class MergeUndoCommand : public RWMolecule::UndoCommand
{
  bool m_canMerge;

public:
  MergeUndoCommand(RWMolecule& m)
    : UndoCommand(m)
    , m_canMerge(false)
  {}
  void setCanMerge(bool merge) { m_canMerge = merge; }
  bool canMerge() const { return m_canMerge; }
  int id() const override { return m_canMerge ? Id : -1; }
};
} // end anon namespace

RWMolecule::RWMolecule(Molecule& mol, QObject* p)
  : QObject(p)
  , m_molecule(mol)
{}

RWMolecule::~RWMolecule() {}

namespace {
class AddAtomCommand : public RWMolecule::UndoCommand
{
  unsigned char m_atomicNumber;
  bool m_usingPositions;
  Index m_atomId;
  Index m_uniqueId;

public:
  AddAtomCommand(RWMolecule& m, unsigned char aN, bool usingPositions,
                 Index atomId, Index uid)
    : UndoCommand(m)
    , m_atomicNumber(aN)
    , m_usingPositions(usingPositions)
    , m_atomId(atomId)
    , m_uniqueId(uid)
  {}

  void redo() override
  {
    assert(atomicNumbers().size() == m_atomId);
    atomicNumbers().push_back(m_atomicNumber);
    if (m_usingPositions)
      positions3d().push_back(Vector3::Zero());
    if (m_uniqueId >= atomUniqueIds().size())
      atomUniqueIds().resize(m_uniqueId + 1, MaxIndex);
    atomUniqueIds()[m_uniqueId] = m_atomId;
  }

  void undo() override
  {
    assert(atomicNumbers().size() == m_atomId + 1);
    atomicNumbers().pop_back();
    if (m_usingPositions)
      positions3d().resize(atomicNumbers().size(), Vector3::Zero());
    atomUniqueIds()[m_uniqueId] = MaxIndex;
  }
};
} // end anon namespace

RWMolecule::AtomType RWMolecule::addAtom(unsigned char num, bool usingPositions)
{
  Index atomId = static_cast<Index>(m_molecule.m_atomicNumbers.size());
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

namespace {
class RemoveAtomCommand : public RWMolecule::UndoCommand
{
  Index m_atomId;
  Index m_atomUid;
  unsigned char m_atomicNumber;
  Vector3 m_position3d;

public:
  RemoveAtomCommand(RWMolecule& m, Index atomId, Index uid, unsigned char aN,
                    const Vector3& pos)
    : UndoCommand(m)
    , m_atomId(atomId)
    , m_atomUid(uid)
    , m_atomicNumber(aN)
    , m_position3d(pos)
  {}

  void redo() override
  {
    assert(m_atomUid < atomUniqueIds().size());
    atomUniqueIds()[m_atomUid] = MaxIndex;

    // Move the last atom to the removed atom's position:
    Index movedId = m_mol.atomCount() - 1;
    if (m_atomId != movedId) {
      atomicNumbers()[m_atomId] = atomicNumbers().back();
      if (positions3d().size() == atomicNumbers().size())
        positions3d()[m_atomId] = positions3d().back();

      // Update any bond pairs that have changed:
      Array<RWMolecule::BondType> atomBonds = m_mol.bonds(movedId);
      for (Array<RWMolecule::BondType>::const_iterator it = atomBonds.begin(),
                                                       itEnd = atomBonds.end();
           it != itEnd; ++it) {
        std::pair<Index, Index>& bondPair = bondPairs()[it->index()];
        if (bondPair.first == movedId)
          bondPair.first = m_atomId;
        else
          bondPair.second = m_atomId;
      }

      // Update the moved atom's uid
      Index movedUid = m_mol.atomUniqueId(movedId);
      assert(movedUid != MaxIndex);
      atomUniqueIds()[movedUid] = m_atomId;
    }

    // Resize the arrays:
    if (positions3d().size() == atomicNumbers().size())
      positions3d().resize(movedId, Vector3::Zero());
    atomicNumbers().resize(movedId, 0);
  }

  void undo() override
  {
    // Append removed atom's info to the end of the arrays:
    if (positions3d().size() == atomicNumbers().size())
      positions3d().push_back(m_position3d);
    atomicNumbers().push_back(m_atomicNumber);

    // Swap the moved and unremoved atom data if needed
    Index movedId = m_mol.atomCount() - 1;
    if (m_atomId != movedId) {
      using std::swap;
      if (positions3d().size() == atomicNumbers().size())
        swap(positions3d()[m_atomId], positions3d().back());
      swap(atomicNumbers()[m_atomId], atomicNumbers().back());

      // Update any bond pairs that have changed:
      Array<RWMolecule::BondType> atomBonds(m_mol.bonds(m_atomId));
      for (Array<RWMolecule::BondType>::iterator it = atomBonds.begin(),
                                                 itEnd = atomBonds.end();
           it != itEnd; ++it) {
        std::pair<Index, Index>& bondPair = bondPairs()[it->index()];
        if (bondPair.first == m_atomId)
          bondPair.first = movedId;
        else
          bondPair.second = movedId;
      }

      // Update the moved atom's UID
      Index movedUid = m_mol.atomUniqueId(m_atomId);
      assert(movedUid != MaxIndex);
      atomUniqueIds()[movedUid] = movedId;
    }

    // Update the removed atom's UID
    atomUniqueIds()[m_atomUid] = m_atomId;
  }
};
} // end anon namespace

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

namespace {
class SetAtomicNumbersCommand : public RWMolecule::UndoCommand
{
  Core::Array<unsigned char> m_oldAtomicNumbers;
  Core::Array<unsigned char> m_newAtomicNumbers;

public:
  SetAtomicNumbersCommand(RWMolecule& m,
                          const Core::Array<unsigned char>& oldAtomicNumbers,
                          const Core::Array<unsigned char>& newAtomicNumbers)
    : UndoCommand(m)
    , m_oldAtomicNumbers(oldAtomicNumbers)
    , m_newAtomicNumbers(newAtomicNumbers)
  {}

  void redo() override { atomicNumbers() = m_newAtomicNumbers; }

  void undo() override { atomicNumbers() = m_oldAtomicNumbers; }
};
} // end anon namespace

bool RWMolecule::setAtomicNumbers(const Core::Array<unsigned char>& nums)
{
  if (nums.size() != m_molecule.m_atomicNumbers.size())
    return false;

  SetAtomicNumbersCommand* comm =
    new SetAtomicNumbersCommand(*this, m_molecule.m_atomicNumbers, nums);
  comm->setText(tr("Change Elements"));
  m_undoStack.push(comm);
  return true;
}

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
    : UndoCommand(m)
    , m_atomId(atomId)
    , m_oldAtomicNumber(oldAtomicNumber)
    , m_newAtomicNumber(newAtomicNumber)
  {}

  void redo() override { atomicNumbers()[m_atomId] = m_newAtomicNumber; }

  void undo() override { atomicNumbers()[m_atomId] = m_oldAtomicNumber; }
};
} // end anon namespace

bool RWMolecule::setAtomicNumber(Index atomId, unsigned char num)
{
  if (atomId >= atomCount())
    return false;

  SetAtomicNumberCommand* comm = new SetAtomicNumberCommand(
    *this, atomId, m_molecule.m_atomicNumbers[atomId], num);
  comm->setText(tr("Change Element"));
  m_undoStack.push(comm);
  return true;
}

namespace {
class SetPositions3dCommand : public MergeUndoCommand<SetPositions3dMergeId>
{
  Core::Array<Vector3> m_oldPositions3d;
  Core::Array<Vector3> m_newPositions3d;

public:
  SetPositions3dCommand(RWMolecule& m,
                        const Core::Array<Vector3>& oldPositions3d,
                        const Core::Array<Vector3>& newPositions3d)
    : MergeUndoCommand<SetPositions3dMergeId>(m)
    , m_oldPositions3d(oldPositions3d)
    , m_newPositions3d(newPositions3d)
  {}

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
} // end anon namespace

bool RWMolecule::setAtomPositions3d(const Core::Array<Vector3>& pos,
                                    const QString& undoText)
{
  if (pos.size() != m_molecule.m_atomicNumbers.size())
    return false;

  SetPositions3dCommand* comm =
    new SetPositions3dCommand(*this, m_molecule.m_positions3d, pos);
  comm->setText(undoText);
  comm->setCanMerge(m_interactive);
  m_undoStack.push(comm);
  return true;
}

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
    : MergeUndoCommand<SetPosition3dMergeId>(m)
    , m_atomIds(1, atomId)
    , m_oldPosition3ds(1, oldPosition3d)
    , m_newPosition3ds(1, newPosition3d)
  {}

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
} // end anon namespace

bool RWMolecule::setAtomPosition3d(Index atomId, const Vector3& pos,
                                   const QString& undoText)
{
  if (atomId >= atomCount())
    return false;

  if (m_molecule.m_positions3d.size() != m_molecule.m_atomicNumbers.size())
    m_molecule.m_positions3d.resize(m_molecule.m_atomicNumbers.size(),
                                    Vector3::Zero());

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

namespace {
class SetAtomHybridizationCommand : public RWMolecule::UndoCommand
{
  Index m_atomId;
  Core::AtomHybridization m_oldHybridization;
  Core::AtomHybridization m_newHybridization;

public:
  SetAtomHybridizationCommand(RWMolecule& m, Index atomId,
                              Core::AtomHybridization oldHybridization,
                              Core::AtomHybridization newHybridization)
    : UndoCommand(m)
    , m_atomId(atomId)
    , m_oldHybridization(oldHybridization)
    , m_newHybridization(newHybridization)
  {}

  void redo() override { hybridizations()[m_atomId] = m_newHybridization; }

  void undo() override { hybridizations()[m_atomId] = m_oldHybridization; }
};
} // end anon namespace

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

namespace {
class SetAtomFormalChargeCommand : public RWMolecule::UndoCommand
{
  Index m_atomId;
  signed char m_oldCharge;
  signed char m_newCharge;

public:
  SetAtomFormalChargeCommand(RWMolecule& m, Index atomId, signed char oldCharge,
                             signed char newCharge)
    : UndoCommand(m)
    , m_atomId(atomId)
    , m_oldCharge(oldCharge)
    , m_newCharge(newCharge)
  {}

  void redo() override { formalCharges()[m_atomId] = m_newCharge; }

  void undo() override { formalCharges()[m_atomId] = m_oldCharge; }
};
} // end anon namespace

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

namespace {
class AddBondCommand : public RWMolecule::UndoCommand
{
  unsigned char m_bondOrder;
  std::pair<Index, Index> m_bondPair;
  Index m_bondId;
  Index m_uniqueId;

public:
  AddBondCommand(RWMolecule& m, unsigned char order,
                 const std::pair<Index, Index>& bondPair, Index bondId,
                 Index uid)
    : UndoCommand(m)
    , m_bondOrder(order)
    , m_bondPair(bondPair)
    , m_bondId(bondId)
    , m_uniqueId(uid)
  {}

  void redo() override
  {
    assert(bondOrders().size() == m_bondId);
    assert(bondPairs().size() == m_bondId);
    bondOrders().push_back(m_bondOrder);
    bondPairs().push_back(m_bondPair);
    if (m_uniqueId >= bondUniqueIds().size())
      bondUniqueIds().resize(m_uniqueId + 1, MaxIndex);
    bondUniqueIds()[m_uniqueId] = m_bondId;
  }

  void undo() override
  {
    assert(bondOrders().size() == m_bondId + 1);
    assert(bondPairs().size() == m_bondId + 1);
    bondOrders().pop_back();
    bondPairs().pop_back();
    bondUniqueIds()[m_uniqueId] = MaxIndex;
  }
};

// Make an std::pair where the lower index is always first in the pair. This
// offers us the guarantee that any given pair of atoms will always result in
// a pair that is the same no matter what the order of the atoms given.
inline std::pair<Index, Index> makeBondPair(Index a, Index b)
{
  return a < b ? std::make_pair(a, b) : std::make_pair(b, a);
}
} // end anon namespace

RWMolecule::BondType RWMolecule::addBond(Index atom1, Index atom2,
                                         unsigned char order)
{
  if (atom1 == atom2 || std::max(atom1, atom2) >= atomCount())
    return BondType();

  Index bondId = bondCount();
  Index bondUid = static_cast<Index>(m_molecule.m_bondUniqueIds.size());

  AddBondCommand* comm = new AddBondCommand(
    *this, order, makeBondPair(atom1, atom2), bondId, bondUid);
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
    : UndoCommand(m)
    , m_bondId(bondId)
    , m_bondUid(bondUid)
    , m_bondPair(bondPair)
    , m_bondOrder(bondOrder)
  {}

  void redo() override
  {
    // Clear removed bond's UID
    bondUniqueIds()[m_bondUid] = MaxIndex;

    // Move the last bond's data to the removed bond's index:
    Index movedId = m_mol.bondCount() - 1;
    if (m_bondId != movedId) {
      bondOrders()[m_bondId] = bondOrders().back();
      bondPairs()[m_bondId] = bondPairs().back();

      // Update moved bond's UID
      Index movedUid = m_mol.bondUniqueId(movedId);
      assert(movedUid != MaxIndex);
      bondUniqueIds()[movedUid] = m_bondId;
    }
    bondOrders().pop_back();
    bondPairs().pop_back();
  }

  void undo() override
  {
    // Push the removed bond's info to the end of the arrays:
    bondOrders().push_back(m_bondOrder);
    bondPairs().push_back(m_bondPair);

    // Swap with the bond that we moved in redo():
    Index movedId = m_mol.bondCount() - 1;
    if (m_bondId != movedId) {
      using std::swap;
      swap(bondOrders()[m_bondId], bondOrders().back());
      swap(bondPairs()[m_bondId], bondPairs().back());

      // Update moved bond's UID
      Index movedUid = m_mol.bondUniqueId(m_bondId);
      assert(movedUid != MaxIndex);
      bondUniqueIds()[movedUid] = movedId;
    }

    // Restore the removed bond's UID
    bondUniqueIds()[m_bondUid] = m_bondId;
  }
};
} // end anon namespace

bool RWMolecule::removeBond(Index bondId)
{
  if (bondId >= bondCount())
    return false;

  Index bondUid = findBondUniqueId(bondId);
  if (bondUid == MaxIndex)
    return false;

  RemoveBondCommand* comm = new RemoveBondCommand(
    *this, bondId, bondUid, m_molecule.m_bondPairs[bondId],
    m_molecule.m_bondOrders[bondId]);
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

namespace {
class SetBondOrdersCommand : public RWMolecule::UndoCommand
{
  Array<unsigned char> m_oldBondOrders;
  Array<unsigned char> m_newBondOrders;

public:
  SetBondOrdersCommand(RWMolecule& m, const Array<unsigned char>& oldBondOrders,
                       const Array<unsigned char>& newBondOrders)
    : UndoCommand(m)
    , m_oldBondOrders(oldBondOrders)
    , m_newBondOrders(newBondOrders)
  {}

  void redo() override { bondOrders() = m_newBondOrders; }

  void undo() override { bondOrders() = m_oldBondOrders; }
};
} // end anon namespace

bool RWMolecule::setBondOrders(const Core::Array<unsigned char>& orders)
{
  if (orders.size() != m_molecule.m_bondOrders.size())
    return false;

  SetBondOrdersCommand* comm =
    new SetBondOrdersCommand(*this, m_molecule.m_bondOrders, orders);
  comm->setText(tr("Set Bond Orders"));
  m_undoStack.push(comm);
  return true;
}

namespace {
class SetBondOrderCommand : public MergeUndoCommand<SetBondOrderMergeId>
{
  Index m_bondId;
  unsigned char m_oldBondOrder;
  unsigned char m_newBondOrder;

public:
  SetBondOrderCommand(RWMolecule& m, Index bondId, unsigned char oldBondOrder,
                      unsigned char newBondOrder)
    : MergeUndoCommand<SetBondOrderMergeId>(m)
    , m_bondId(bondId)
    , m_oldBondOrder(oldBondOrder)
    , m_newBondOrder(newBondOrder)
  {}

  void redo() override { bondOrders()[m_bondId] = m_newBondOrder; }

  void undo() override { bondOrders()[m_bondId] = m_oldBondOrder; }

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
} // end anon namespace

bool RWMolecule::setBondOrder(Index bondId, unsigned char order)
{
  if (bondId >= bondCount())
    return false;

  SetBondOrderCommand* comm = new SetBondOrderCommand(
    *this, bondId, m_molecule.m_bondOrders[bondId], order);
  comm->setText(tr("Change Bond Order"));
  // Always allow merging, but only if bondId is the same.
  comm->setCanMerge(true);
  m_undoStack.push(comm);
  return true;
}

namespace {
class SetBondPairsCommand : public RWMolecule::UndoCommand
{
  Array<std::pair<Index, Index>> m_oldBondPairs;
  Array<std::pair<Index, Index>> m_newBondPairs;

public:
  SetBondPairsCommand(RWMolecule& m,
                      const Array<std::pair<Index, Index>>& oldBondPairs,
                      const Array<std::pair<Index, Index>>& newBondPairs)
    : UndoCommand(m)
    , m_oldBondPairs(oldBondPairs)
    , m_newBondPairs(newBondPairs)
  {}

  void redo() override { bondPairs() = m_newBondPairs; }

  void undo() override { bondPairs() = m_oldBondPairs; }
};
} // end anon namespace

bool RWMolecule::setBondPairs(const Array<std::pair<Index, Index>>& pairs)
{
  if (pairs.size() != m_molecule.m_bondPairs.size())
    return false;

  // Correct any pairs that are ordered improperly:
  typedef std::pair<Index, Index> BondPair;
  Array<BondPair> p(pairs);
  // Use for reading to prevent copies unless needed (Array is copy-on-write):
  const Array<BondPair>& p_const = p;
  using std::swap;
  for (size_t i = 0; i < p.size(); ++i)
    if (p_const[i].first > p_const[i].second)
      swap(p[i].first, p[i].second);

  SetBondPairsCommand* comm =
    new SetBondPairsCommand(*this, m_molecule.m_bondPairs, p);
  comm->setText(tr("Update Bonds"));
  m_undoStack.push(comm);
  return true;
}

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
    : UndoCommand(m)
    , m_bondId(bondId)
    , m_oldBondPair(oldBondPair)
    , m_newBondPair(newBondPair)
  {}

  void redo() override { bondPairs()[m_bondId] = m_newBondPair; }

  void undo() override { bondPairs()[m_bondId] = m_oldBondPair; }
};
} // end anon namespace

bool RWMolecule::setBondPair(Index bondId, const std::pair<Index, Index>& pair)
{
  if (bondId >= bondCount() || pair.first == pair.second)
    return false;

  SetBondPairCommand* comm = nullptr;
  if (pair.first < pair.second) {
    comm = new SetBondPairCommand(*this, bondId, m_molecule.m_bondPairs[bondId],
                                  pair);
  } else {
    comm = new SetBondPairCommand(*this, bondId, m_molecule.m_bondPairs[bondId],
                                  makeBondPair(pair.first, pair.second));
  }
  comm->setText(tr("Update Bond"));
  m_undoStack.push(comm);
  return true;
}

namespace {
class AddUnitCellCommand : public RWMolecule::UndoCommand
{
  UnitCell m_newUnitCell;

public:
  AddUnitCellCommand(RWMolecule& m, const UnitCell& newUnitCell)
    : UndoCommand(m)
    , m_newUnitCell(newUnitCell)
  {}

  void redo() override
  {
    m_mol.molecule().setUnitCell(new UnitCell(m_newUnitCell));
  }

  void undo() override { m_mol.molecule().setUnitCell(nullptr); }
};
} // end anon namespace

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

namespace {
class RemoveUnitCellCommand : public RWMolecule::UndoCommand
{
  UnitCell m_oldUnitCell;

public:
  RemoveUnitCellCommand(RWMolecule& m, const UnitCell& oldUnitCell)
    : UndoCommand(m)
    , m_oldUnitCell(oldUnitCell)
  {}

  void redo() override { m_mol.molecule().setUnitCell(nullptr); }

  void undo() override
  {
    m_mol.molecule().setUnitCell(new UnitCell(m_oldUnitCell));
  }
};
} // end anon namespace

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

namespace {
class ModifyMoleculeCommand : public RWMolecule::UndoCommand
{
  Molecule m_oldMolecule;
  Molecule m_newMolecule;

public:
  ModifyMoleculeCommand(RWMolecule& m, const Molecule& oldMolecule,
                        const Molecule& newMolecule)
    : UndoCommand(m)
    , m_oldMolecule(oldMolecule)
    , m_newMolecule(newMolecule)
  {}

  void redo() override { m_mol.molecule() = m_newMolecule; }

  void undo() override { m_mol.molecule() = m_oldMolecule; }
};
} // end anon namespace

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

} // namespace QtGui
} // namespace Avogadro
