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

#ifndef AVOGADRO_QTGUI_RWMOLECULE_H
#define AVOGADRO_QTGUI_RWMOLECULE_H

#include <QtCore/QObject>
#include "avogadroqtguiexport.h"

#include "persistentatom.h"
#include "persistentbond.h"

#include <avogadro/core/array.h>
#include <avogadro/core/atom.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include <QtWidgets/QUndoStack>

namespace Avogadro {
namespace QtGui {

/** Concrete atom/bond proxy classes for RWMolecule. @{ */
class RWAtom;
class RWBond;
/** @} */

/**
 * @class RWMolecule rwmolecule.h <avogadro/qtgui/rwmolecule.h>
 * @brief The RWMolecule class is an editable molecule class that automatically
 * populates an undo stack.
 *
 * This class implements the molecule API and composes a QUndoStack
 * (undoStack()). New undo commands are automatically generated and push each
 * time a non-const method is called.
 *
 * An interactive mode is supported that causes "noisy" commands, such as
 * atom position changes, to be merged into a single command, saving memory
 * keeping the stack usable during interactive editing of the molecule. Use
 * setInteractive(bool) to toggle interactive mode.
 *
 * Similarly, multiple sequences of commands can be compressed into a single
 * named action using the QUndoStack's macro capability. Call
 * undoStack().beginMacro(tr("User Description Of Change")) to begin a macro,
 * and undoStack().endMacro() when finished.
 */
class AVOGADROQTGUI_EXPORT RWMolecule : public QObject
{
  Q_OBJECT
public:
  /** Typedef for Atom class. */
  typedef RWAtom AtomType;

  /** Typedef for PersistentAtom class. */
  typedef PersistentAtom<RWMolecule> PersistentAtomType;

  /** Typedef for Bond class. */
  typedef RWBond BondType;

  /** Typedef for PersistentBond class. */
  typedef PersistentBond<RWMolecule> PersistentBondType;

  /** Construct a empty molecule with a clean undo stack. */
  explicit RWMolecule(QObject *parent = 0);

  ~RWMolecule() AVO_OVERRIDE;

  /**
   * Add a new atom to the molecule.
   * @param atomicNumber The atomic number of the new atom.
   * @return The new Atom object.
   */
  AtomType addAtom(unsigned char atomicNumber);

  /**
   * Obtain an atom object.
   * @param atomId The index of the atom to return.
   * @return The requested atom object. Will be invalid if @a atomId >= @a
   * atomCount().
   */
  AtomType atom(Index atomId) const;

  /**
   * Obtain an atom object from it's unique id.
   * @param atomUId The unique of the requested atom.
   * @return The requested atom object. Will be invalid if @a atomUId is not
   * in use.
   */
  AtomType atomByUniqueId(Index atomUId) const;

  /**
   * @return The unique id of the atom.
   * @{
   */
  Index atomUniqueId(Index atomId) const;
  Index atomUniqueId(const AtomType &atom) const;
  /** @} */

  /**
   * @return The number of atoms in the molecule.
   */
  Index atomCount() const;

  /**
   * @return The number of atoms in the molecule with the atomic number @a
   * atomicNumber.
   */
  Index atomCount(unsigned char atomicNumber) const;

  /**
   * Delete the specified atom from this molecule.
   * @return True on success, false otherwise.
   * @note This also removes all bonds connected to the atom.
   * @{
   */
  bool removeAtom(Index atomId);
  bool removeAtom(const AtomType &atom);
  /** @} */

  /**
   * Delete all atoms from this molecule.
   * @note This also removes all bonds.
   */
  void clearAtoms();

  /**
   * @return An array containing atomic numbers for all atoms in the molecule,
   * indexed by atom index.
   */
  const Core::Array<unsigned char>& atomicNumbers() const;

  /**
   * Get the atomic number for the requested atom.
   * @param atomId The index of the atom.
   * @return The atomic number of the atom indexed at @a atomId, or
   * Avogadro::InvalidElement if @a atomId is invalid.
   */
  unsigned char atomicNumber(Index atomId) const;

  /**
   * Replace the current array of atomic numbers.
   * @param nums The new atomic number array. Must be of length atomCount().
   * @return True on success, false otherwise.
   */
  bool setAtomicNumbers(const Core::Array<unsigned char> &nums);

  /**
   * Set the atomic number of a single atom.
   * @param atomId The index of the atom to modify.
   * @param atomicNumber The new atomic number.
   * @return True on success, false otherwise.
   */
  bool setAtomicNumber(Index atomId, unsigned char atomicNumber);

  /**
   * @return An array containing 3D coordinates for all atoms in the molecule,
   * indexed by atom index.
   * @note May be empty if position information has not been set for any atoms.
   */
  const Core::Array<Vector3>& atomPositions3d() const;

  /**
   * Get the 3D position of a single atom.
   * @param atomId The index of the atom.
   * @return The position of the atom, or Vector3::Zero() if no position
   * information has been set.
   */
  Vector3 atomPosition3d(Index atomId) const;

  /**
   * Replace the current array of 3D atomic coordinates.
   * @param pos The new coordinate array. Must be of length atomCount().
   * @return True on success, false otherwise.
   */
  bool setAtomPositions3d(const Core::Array<Vector3> &pos);

  /**
   * Set the 3D position of a single atom.
   * @param atomId The index of the atom to modify.
   * @param pos The new position of the atom.
   * @return True on success, false otherwise.
   */
  bool setAtomPosition3d(Index atomId, const Vector3& pos);

  /**
   * Create a new bond in the molecule.
   * @param atom1 The first atom in the bond.
   * @param atom2 The second order in the bond.
   * @param order The bond order.
   * @return The new bond object. Will be invalid if @a atom1 or @a atom2 does
   * not exist.
   * @{
   */
  BondType addBond(Index atom1, Index atom2, unsigned char order = 1);
  BondType addBond(const AtomType &atom1, const AtomType &atom2,
                   unsigned char order = 1);
  /** @} */

  /**
   * Get a bond object.
   * @param bondId The index of the requested bond.
   * @return The requested bond object. Will be invalid if @a bondId >=
   * @a bondCount().
   */
  BondType bond(Index bondId) const;

  /**
   * Get a bond object.
   * @param atom1 The index of one atom in the bond.
   * @param atom2 The index of the other atom in bond.
   * @return The requested bond object. Will be invalid if @a atom1 or @a atom2
   * do not exist.
   */
  BondType bond(Index atom1, Index atom2) const;

  /**
   * Get a bond object.
   * @param atom1 One atom in the bond.
   * @param atom2 The other atom in bond.
   * @return The requested bond object. Will be invalid if @a atom1 or @a atom2
   * are invalid.
   */
  BondType bond(const AtomType &atom1, const AtomType &atom2) const;

  /**
   * Get a bond object from its unique id.
   * @param bondUid The unique id of the bond.
   * @return The requested bond object. Will be invalid if @a bondUid is not in
   * use.
   */
  BondType bondByUniqueId(Index bondUid) const;

  /**
   * Get the unique id of a bond.
   * @param bondId The index of the requested bond.
   * @return The unique id currently assigned to the bond at index @a bondId
   */
  Index bondUniqueId(Index bondId) const;

  /**
   * Get the unique id of a bond.
   * @param bond The requested bond object.
   * @return The unique id currently assigned to @a bond.
   */
  Index bondUniqueId(const BondType &bond) const;

  /**
   * @return The number of bonds in the molecule.
   */
  Index bondCount() const;

  /**
   * Remove the requested bond.
   * @return True on success, false otherwise.
   * @{
   */
  bool removeBond(Index bondId);
  bool removeBond(const BondType &bond);
  bool removeBond(Index atom1, Index atom2);
  bool removeBond(const AtomType &atom1, const AtomType &atom2);
  /** @} */

  /**
   * Remove all bonds from the molecule.
   */
  void clearBonds();

  /**
   * Find bonds connected to an atom.
   * @param atom The atom of interest.
   * @return An array of bond objects that are attached to the specified atom.
   */
  Core::Array<BondType> bonds(const AtomType &atom) const;

  /**
   * Find bonds connected to an atom.
   * @param atomId The index for the atom of interest.
   * @return An array of bond objects that are attached to the specified atom.
   */
  Core::Array<BondType> bonds(const Index &atomId) const;

  /**
   * @return An array of bond orders for all bonds in the molecule, indexed by
   * bond index.
   */
  const Core::Array<unsigned char>& bondOrders() const;

  /**
   * Get the order of a bond.
   * @param bondId The id of the bond.
   * @return The bond order.
   */
  unsigned char bondOrder(Index bondId) const;

  /**
   * Replace the current array of bond orders.
   * @param orders The new array.
   * @return True on success, false on failure.
   */
  bool setBondOrders(const Core::Array<unsigned char> &orders);

  /**
   * Set the order of a bond in the molecule.
   * @param bondId The bond's index.
   * @param order The new order of the bond.
   * @return True on success, false on failure.
   */
  bool setBondOrder(Index bondId, unsigned char order);

  /**
   * @return An array of all bonded atoms in the molecule, indexed by bond
   * index.
   * Each bond pair is represented by a pair of atom indices.
   */
  const Core::Array<std::pair<Index, Index> >& bondPairs() const;

  /**
   * Get the set of bonded atoms corresponding to @a bondId.
   * @param bondId The index of the requested bond.
   * @return The bonded atom pair, represented as a pair of atom indices.
   */
  std::pair<Index, Index> bondPair(Index bondId) const;

  /**
   * Replace the current array of bonded atoms.
   * @param pairs The array.
   * @return True on success, false on failure.
   * @note The bonded atoms are represented as a pair of bond indices.
   * @note If needed, the elements in @a pairs will be modified to ensure that
   * the first atom index is less than the second.
   */
  bool setBondPairs(const Core::Array<std::pair<Index, Index> > &pairs);

  /**
   * Set the bonded atoms for a bond.
   * @param bondId The bond to modify.
   * @param pair The new bond pair.
   * @return True on success, false otherwise.
   * @note If needed, @a pair will be modified to ensure that the first atom
   * index is less than the second.
   */
  bool setBondPair(Index bondId, const std::pair<Index, Index> &pair);

  /**
   * @brief Begin or end an interactive edit.
   *
   * If enabled, certain undo operations will be merged together. For instance,
   * an editor dragging an atom through space in response to mouse movement will
   * only generate a single undo command containing the initial and final
   * positions and discard the intermediate states. If disabled, each
   * intermediate action will appear in the undo log.
   */
  void setInteractive(bool b);

  /**
   * @return True if interactive mode is enabled, false otherwise.
   * @sa setInteractive
   */
  bool isInteractive() const;

  /**
   * @return The QUndoStack for this molecule.
   * @{
   */
  QUndoStack& undoStack();
  const QUndoStack& undoStack() const;
  /** @} */

  class UndoCommand;
  friend class UndoCommand;

public slots:
  /**
   * @brief Force the molecule to emit the changed() signal.
   * @param change See changed().
   */
  void emitChanged(unsigned int change);

signals:
  /**
   * @brief Indicates that the molecule has changed.
   * @param change Use the MoleculeChange enum to check what has changed.
   *
   * The @p change variable indicates what has changed, i.e. if
   * change & Atoms == true then atoms were changed in some way, and if
   * change & Removed == true then one or more atoms were removed.
   */
  void changed(unsigned int change);

protected:
  Index findAtomUniqueId(Index atomId) const;
  Index findBondUniqueId(Index bondId) const;

  Core::Array<Index> m_atomUniqueIds;
  Core::Array<Index> m_bondUniqueIds;
  Core::Array<unsigned char> m_atomicNumbers;
  Core::Array<Vector3> m_positions3d;
  Core::Array<std::pair<Index, Index> > m_bondPairs;
  Core::Array<unsigned char> m_bondOrders;
  Core::UnitCell *m_unitCell;
  bool m_interactive;

  QUndoStack m_undoStack;
};

class AVOGADROQTGUI_EXPORT RWAtom : public Core::AtomTemplate<RWMolecule>
{
public:
  RWAtom() : Core::AtomTemplate<RWMolecule>() {}
  RWAtom(RWMolecule *m, Index i) : Core::AtomTemplate<RWMolecule>(m, i) {}
};

class AVOGADROQTGUI_EXPORT RWBond : public Core::BondTemplate<RWMolecule>
{
public:
  RWBond() : Core::BondTemplate<RWMolecule>() {}
  RWBond(RWMolecule *m, Index i) : Core::BondTemplate<RWMolecule>(m, i) {}
};

inline RWMolecule::AtomType RWMolecule::atom(Index atomId) const
{
  return AtomType(const_cast<RWMolecule*>(this), atomId);
}

inline RWMolecule::AtomType RWMolecule::atomByUniqueId(Index atomUId) const
{
  return atomUId < m_atomUniqueIds.size()
      ? AtomType(const_cast<RWMolecule*>(this), m_atomUniqueIds[atomUId])
      : AtomType();
}

inline Index RWMolecule::atomUniqueId(Index atomId) const
{
  return findAtomUniqueId(atomId);
}

inline Index RWMolecule::atomUniqueId(const RWMolecule::AtomType &a) const
{
  return a.molecule() == this ? findAtomUniqueId(a.index()) : MaxIndex;
}

inline Index RWMolecule::atomCount() const
{
  return m_atomicNumbers.size();
}

inline bool RWMolecule::removeAtom(const AtomType &a)
{
  return a.molecule() == this ? removeAtom(a.index()) : false;
}

inline const Core::Array<unsigned char> &RWMolecule::atomicNumbers() const
{
  return m_atomicNumbers;
}

inline unsigned char RWMolecule::atomicNumber(Index atomId) const
{
  return atomId < m_atomicNumbers.size() ? m_atomicNumbers[atomId]
                                         : InvalidElement;
}

inline const Core::Array<Vector3> &RWMolecule::atomPositions3d() const
{
  return m_positions3d;
}

inline Vector3 RWMolecule::atomPosition3d(Index atomId) const
{
  return atomId < m_positions3d.size() ? m_positions3d[atomId] : Vector3();
}

inline RWMolecule::BondType RWMolecule::addBond(const AtomType &atom1,
                                                const AtomType &atom2,
                                                unsigned char order)
{
  if (atom1.molecule() != atom2.molecule() || atom1.molecule() != this)
    return BondType();
  return addBond(atom1.index(), atom2.index(), order);
}

inline RWMolecule::BondType RWMolecule::bond(Index bondId) const
{
  return BondType(const_cast<RWMolecule*>(this), bondId);
}

inline RWMolecule::BondType RWMolecule::bond(
    const RWMolecule::AtomType &atom1, const RWMolecule::AtomType &atom2) const
{
  if (atom1.molecule() == atom2.molecule() && atom1.molecule() == this)
    return bond(atom1.index(), atom2.index());
  return BondType();
}

inline RWMolecule::BondType RWMolecule::bondByUniqueId(Index bondUid) const
{
  return bondUid < m_bondUniqueIds.size()
      ? BondType(const_cast<RWMolecule*>(this), m_bondUniqueIds[bondUid])
      : BondType();
}

inline Index RWMolecule::bondUniqueId(Index bondId) const
{
  return findBondUniqueId(bondId);
}

inline Index RWMolecule::bondUniqueId(const RWMolecule::BondType &b) const
{
  return b.molecule() == this ? findBondUniqueId(b.index()) : MaxIndex;
}

inline Index RWMolecule::bondCount() const
{
  return m_bondOrders.size();
}

inline bool RWMolecule::removeBond(const RWMolecule::BondType &b)
{
  return b.molecule() == this ? removeBond(b.index()) : false;
}

inline bool RWMolecule::removeBond(Index atom1, Index atom2)
{
  return removeBond(bond(atom1, atom2).index());
}

inline bool RWMolecule::removeBond(const RWMolecule::AtomType &atom1,
                                   const RWMolecule::AtomType &atom2)
{
  if (atom1.molecule() != atom2.molecule() || atom1.molecule() != this)
    return false;
  return removeBond(bond(atom1.index(), atom2.index()).index());
}

inline Core::Array<RWMolecule::BondType>
RWMolecule::bonds(const RWMolecule::AtomType &a) const
{
  return a.molecule() == this ? bonds(a.index()) : Core::Array<BondType>();
}

inline Core::Array<RWMolecule::BondType>
RWMolecule::bonds(const Index &atomId) const
{
  Core::Array<RWMolecule::BondType> result;
  for (Index i = 0; i < m_bondPairs.size(); ++i)
    if (m_bondPairs[i].first == atomId || m_bondPairs[i].second == atomId)
      result.push_back(BondType(const_cast<RWMolecule*>(this), i));
  return result;
}

inline const Core::Array<unsigned char> &RWMolecule::bondOrders() const
{
  return m_bondOrders;
}

inline unsigned char RWMolecule::bondOrder(Index bondId) const
{
  return bondId < m_bondOrders.size() ? m_bondOrders[bondId] : 0;
}

inline const Core::Array<std::pair<Index, Index> > &
RWMolecule::bondPairs() const
{
  return m_bondPairs;
}

inline std::pair<Index, Index> RWMolecule::bondPair(Index bondId) const
{
  return bondId < m_bondPairs.size() ? m_bondPairs[bondId]
                                       : std::make_pair(MaxIndex, MaxIndex);
}

inline void RWMolecule::setInteractive(bool b)
{
  m_interactive = b;
}

inline bool RWMolecule::isInteractive() const
{
  return m_interactive;
}

inline QUndoStack &RWMolecule::undoStack()
{
  return m_undoStack;
}

inline const QUndoStack &RWMolecule::undoStack() const
{
  return m_undoStack;
}

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_RWMOLECULE_H
