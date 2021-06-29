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

#ifndef AVOGADRO_QTGUI_RWMOLECULE_H
#define AVOGADRO_QTGUI_RWMOLECULE_H

#include "avogadroqtguiexport.h"
#include <QtCore/QObject>

#include "molecule.h"
#include "persistentatom.h"
#include "persistentbond.h"

#include <avogadro/core/array.h>
#include <avogadro/core/atom.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/crystaltools.h>
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

  /** Construct a molecule with the atoms/bonds of mol. */
  explicit RWMolecule(Molecule& mol, QObject* parent = nullptr);

  ~RWMolecule() override;

  Molecule& molecule() { return m_molecule; }
  const Molecule& molecule() const { return m_molecule; }

  /**
   * Add a new atom to the molecule.
   * @param atomicNumber The atomic number of the new atom.
   * @param usingPositions Whether or not to use positions for this atom.
   *                       Default is true. Set to false if the atom
   *                       will not be using coordinates.
   * @return The new Atom object.
   */
  AtomType addAtom(unsigned char atomicNumber, bool usingPositions = true);

  /**
   * Add a new atom to the molecule and set its position.
   * @param atomicNumber The atomic number of the new atom.
   * @param position3d The position of the atom.
   * @return The new Atom object.
   */
  AtomType addAtom(unsigned char atomicNumber, const Vector3& position3d);

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
  Index atomUniqueId(const AtomType& atom) const;
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
  bool removeAtom(const AtomType& atom);
  /** @} */

  /**
   * Delete all atoms from this molecule.
   * @note This also removes all bonds.
   */
  void clearAtoms();

  /**
   * Adjust hydrogens for an atom.
   * @param atomId The index of the atom.
   * @note Checks to make sure the atom is valid before adjusting the hydrogens.
   */
  void adjustHydrogens(Index atomId);

  /**
   * Adjust hydrogens for multiple atoms.
   * @param atomIds The indices for the atoms.
   * @note Checks to make sure the atoms are valid before adjusting the
   * hydrogens.
   */
  void adjustHydrogens(const Core::Array<Index>& atomIds);

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
  bool setAtomicNumbers(const Core::Array<unsigned char>& nums);

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
   * @param undoText The undo text to be displayed for undo commands.
   * @return True on success, false otherwise.
   */
  bool setAtomPositions3d(
    const Core::Array<Vector3>& pos,
    const QString& undoText = QStringLiteral("Change Atom Positions"));

  /**
   * Set the 3D position of a single atom.
   * @param atomId The index of the atom to modify.
   * @param pos The new position of the atom.
   * @param undoText The undo text to be displayed for undo commands.
   * @return True on success, false otherwise.
   */
  bool setAtomPosition3d(
    Index atomId, const Vector3& pos,
    const QString& undoText = QStringLiteral("Change Atom Position"));

  /**
   * Set whether the specified atom is selected or not.
   */
  void setAtomSelected(Index atomId, bool selected);

  /**
   * Query whether the supplied atom index has been selected.
   */
  bool atomSelected(Index atomId) const;

  bool setAtomPosition2d(Index, const Vector2&) { return false; }
  Vector2 atomPosition2d(Index) { return Vector2(0, 0); }
  const Core::Array<Vector2>& atomPositions2d() const
  {
    return m_molecule.m_positions2d;
  }

  /**
   * Get the hybridization for the requested atom.
   * @param atomId The index of the atom.
   * @return The hybridization of the atom indexed at @a atomId, or
   * 0 if @a atomId is invalid.
   */
  Core::AtomHybridization hybridization(Index atomId) const;

  /**
   * Set the hybridization of a single atom.
   * @param atomId The index of the atom to modify.
   * @param hyb The new hybridization.
   * @return True on success, false otherwise.
   */
  bool setHybridization(Index atomId, Core::AtomHybridization hyb);

  /**
   * Get the formal charge for the requested atom.
   * @param atomId The index of the atom.
   * @return The formal charge of the atom indexed at @a atomId, or
   * 0 if @a atomId is invalid.
   */
  signed char formalCharge(Index atomId) const;

  /**
   * Set the formal charge of a single atom.
   * @param atomId The index of the atom to modify.
   * @param charge The new formal charge.
   * @return True on success, false otherwise.
   */
  bool setFormalCharge(Index atomId, signed char charge);

  /**
   * Get the color for the requested atom.
   * @param atomId The index of the atom.
   * @return The color of the atom indexed at @a atomId, or
   * (0, 0, 0) if @a atomId is invalid. If no color is set for the
   * given atomId, the default color for the atomic number of
   * the atomId is returned.
   */
  Vector3ub color(Index atomId) const;

  /**
   * Set the color of a single atom.
   * @param atomId The index of the atom to modify.
   * @param color The new color.
   * @return True on success, false otherwise.
   */
  bool setColor(Index atomId, Vector3ub color);

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
  BondType addBond(const AtomType& atom1, const AtomType& atom2,
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
  BondType bond(const AtomType& atom1, const AtomType& atom2) const;

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
  Index bondUniqueId(const BondType& bond) const;

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
  bool removeBond(const BondType& bond);
  bool removeBond(Index atom1, Index atom2);
  bool removeBond(const AtomType& atom1, const AtomType& atom2);
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
  Core::Array<BondType> bonds(const AtomType& atom) const;

  /**
   * Find bonds connected to an atom.
   * @param atomId The index for the atom of interest.
   * @return An array of bond objects that are attached to the specified atom.
   */
  Core::Array<BondType> bonds(const Index& atomId) const;

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
  bool setBondOrders(const Core::Array<unsigned char>& orders);

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
  const Core::Array<std::pair<Index, Index>>& bondPairs() const;

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
  bool setBondPairs(const Core::Array<std::pair<Index, Index>>& pairs);

  /**
   * Set the bonded atoms for a bond.
   * @param bondId The bond to modify.
   * @param pair The new bond pair.
   * @return True on success, false otherwise.
   * @note If needed, @a pair will be modified to ensure that the first atom
   * index is less than the second.
   */
  bool setBondPair(Index bondId, const std::pair<Index, Index>& pair);

  /**
   * Add a default unit cell to the molecule. Does nothing if there already
   * is a unit cell. Changes are emitted.
   */
  void addUnitCell();

  /**
   * Remove the unit cell from the molecule. Does nothing if there is
   * no unit cell. Changes are emitted.
   */
  void removeUnitCell();

  /**
   * Generic edit that changes the current molecule to be @a newMolecule.
   * Also sets the text for the undo command to be @a undoText. Changes are
   * emitted.
   * @param newMolecule The new molecule to be set.
   * @param changes The changes to be emitted.
   * @param undoText The text description for the undo command.
   */
  void modifyMolecule(
    const Molecule& newMolecule, Molecule::MoleculeChanges changes,
    const QString& undoText = QStringLiteral("Modify Molecule"));

  /**
   * Generic edit that adds @a newMolecule to the current molecule.
   * Also sets the text for the undo command to be @a undoText. Changes are
   * emitted.
   * @param addMolecule The new molecule to be set.
   * @param undoText The text description for the undo command.
   */
  void appendMolecule(
    const Molecule& addMolecule,
    const QString& undoText = QStringLiteral("Append Molecule"));

  /**
   * Edit the unit cell by replacing the current cell matrix with a new cell
   * matrix. Changes are emitted.
   * @param cellMatrix The new cell matrix to be set.
   * @param opts If TransformAtoms is specified, the atoms in @a molecule are
   * adjusted so that their fractional (lattice) coordinates are preserved. This
   * option is ignored if the input molecule has no unit cell.
   */
  void editUnitCell(Matrix3 cellMatrix, Core::CrystalTools::Options opts);

  /**
   * Wrap atoms to the unit cell. Changes are emitted.
   */
  void wrapAtomsToCell();

  /**
   * Rotate cell to standard orientation. Changes are emitted.
   */
  void rotateCellToStandardOrientation();

  /**
   * Scale a cell's volume. Changes are emitted.
   * @param newVolume The new volume to be set.
   * @param options If CrystalTools::TransformAtoms is set, then
   *                the atoms will be transformed during the scaling.
   */
  void setCellVolume(double newVolume, Core::CrystalTools::Options options);

  /**
   * Build a supercell. Changes are emitted.
   * @param a The final number of units along the A vector (at least 1).
   * @param b The final number of units along the B vector (at least 1).
   * @param c The final number of units along the C vector (at least 1).
   */
  void buildSupercell(unsigned int a, unsigned int b, unsigned int c);

  /**
   * Perform a Niggli reduction on the cell. Changes are emitted.
   */
  void niggliReduceCell();

  /**
   * Use spglib to reduce the cell to its primitive form. Changes are emitted.
   * @param cartTol Cartesian tolerance for primitive reduction.
   * @return True if the algorithm succeeded, and false if it failed.
   */
  bool reduceCellToPrimitive(double cartTol = 1e-5);

  /**
   * Use spglib to convert the cell to its conventional form. Changes are
   * emitted.
   * @param cartTol Cartesian tolerance for conventionalization.
   * @return True if the algorithm succeeded, and false if it failed.
   */
  bool conventionalizeCell(double cartTol = 1e-5);

  /**
   * Use spglib to symmetrize the cell. Changes are emitted.
   * @param cartTol Cartesian tolerance for symmetrization.
   * @return True if the algorithm succeeded, and false if it failed.
   */
  bool symmetrizeCell(double cartTol = 1e-5);

  /**
   * Fill unit cell using transforms for the space group. Changes are emitted.
   * @param hallNumber The hall number to be used for transforming the cell.
   * @param cartTol Cartesian tolerance for comparing atom positions.
   * @return True if the algorithm succeeded, and false if it failed.
   */
  bool fillUnitCell(unsigned short hallNumber, double cartTol = 1e-5);

  /**
   * Use transforms to reduce a cell to its asymmetric unit. Changes are
   * emitted.
   * @param hallNumber The hall number to be used for obtaining the transforms.
   * @param cartTol Cartesian tolerance for comparing atom positions.
   * @return True if the algorithm succeeded, and false if it failed.
   */
  bool reduceCellToAsymmetricUnit(unsigned short hallNumber,
                                  double cartTol = 1e-5);

  /**
   * Call this function when you wish to merge all undo commands.
   * It turns on interactive mode to merge similar undo commands in a series
   * (in order to save space), and it uses QUndoStack's beginMacro() to merge
   * dissimilar undo commands together. You must call endMergeMode() to end
   * the merging section (undo and redo are unavailable while merge mode is
   * on).
   * @param undoName The name of the undo command
   */
  void beginMergeMode(const QString& undoName = QStringLiteral("Draw"));

  /**
   * Call this function when you wish merge mode to end. This will turn off
   * interactive mode, and it will call QUndoStack's endMacro(). All of the
   * undo commands pushed between beginMergeMode() and endMergeMode() will be
   * merged into one undo command. beginMergeMode() should have been called
   * before this is called.
   */
  void endMergeMode();

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

  /** Returns a vector of forces for the atoms in the molecule. */
  const Core::Array<Vector3>& forceVectors() const;

  /**
   * Replace the current array of force vectors.
   * @param pos The new force vector array. Must be of length atomCount().
   * @param undoText The undo text to be displayed for undo commands.
   * @return True on success, false otherwise.
   */
  bool setForceVector(
    Index atomId, const Vector3& pos,
    const QString& undoText = QStringLiteral("Change Force Vectors"));

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

  /**
   * @brief m_molecule still stored all data, this class acts upon it and builds
   * an undo/redo stack that can be used to offer undo and redo.
   */
  Molecule& m_molecule;
  bool m_interactive;

  QUndoStack m_undoStack;

  friend class Molecule;
};

class AVOGADROQTGUI_EXPORT RWAtom : public Core::AtomTemplate<RWMolecule>
{
public:
  RWAtom() : Core::AtomTemplate<RWMolecule>() {}
  RWAtom(RWMolecule* m, Index i) : Core::AtomTemplate<RWMolecule>(m, i) {}
};

class AVOGADROQTGUI_EXPORT RWBond : public Core::BondTemplate<RWMolecule>
{
public:
  RWBond() : Core::BondTemplate<RWMolecule>() {}
  RWBond(RWMolecule* m, Index i) : Core::BondTemplate<RWMolecule>(m, i) {}
};

inline RWMolecule::AtomType RWMolecule::atom(Index atomId) const
{
  return AtomType(const_cast<RWMolecule*>(this), atomId);
}

inline RWMolecule::AtomType RWMolecule::atomByUniqueId(Index atomUId) const
{
  return atomUId < m_molecule.m_atomUniqueIds.size()
           ? AtomType(const_cast<RWMolecule*>(this),
                      m_molecule.m_atomUniqueIds[atomUId])
           : AtomType();
}

inline Index RWMolecule::atomUniqueId(Index atomId) const
{
  return findAtomUniqueId(atomId);
}

inline Index RWMolecule::atomUniqueId(const RWMolecule::AtomType& a) const
{
  return a.molecule() == this ? findAtomUniqueId(a.index()) : MaxIndex;
}

inline Index RWMolecule::atomCount() const
{
  return m_molecule.atomCount();
}

inline bool RWMolecule::removeAtom(const AtomType& a)
{
  return a.molecule() == this ? removeAtom(a.index()) : false;
}

inline const Core::Array<unsigned char>& RWMolecule::atomicNumbers() const
{
  return m_molecule.atomicNumbers();
}

inline unsigned char RWMolecule::atomicNumber(Index atomId) const
{
  return m_molecule.atomicNumber(atomId);
}

inline const Core::Array<Vector3>& RWMolecule::atomPositions3d() const
{
  return m_molecule.atomPositions3d();
}

inline Vector3 RWMolecule::atomPosition3d(Index atomId) const
{
  return m_molecule.atomPosition3d(atomId);
}

inline Core::AtomHybridization RWMolecule::hybridization(Index atomId) const
{
  return m_molecule.hybridization(atomId);
}

inline signed char RWMolecule::formalCharge(Index atomId) const
{
  return m_molecule.formalCharge(atomId);
}

inline Vector3ub RWMolecule::color(Index atomId) const
{
  return m_molecule.color(atomId);
}

inline RWMolecule::BondType RWMolecule::addBond(const AtomType& atom1,
                                                const AtomType& atom2,
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
  const RWMolecule::AtomType& atom1, const RWMolecule::AtomType& atom2) const
{
  if (atom1.molecule() == atom2.molecule() && atom1.molecule() == this)
    return bond(atom1.index(), atom2.index());
  return BondType();
}

inline RWMolecule::BondType RWMolecule::bondByUniqueId(Index bondUid) const
{
  return bondUid < m_molecule.m_bondUniqueIds.size()
           ? BondType(const_cast<RWMolecule*>(this),
                      m_molecule.m_bondUniqueIds[bondUid])
           : BondType();
}

inline Index RWMolecule::bondUniqueId(Index bondId) const
{
  return findBondUniqueId(bondId);
}

inline Index RWMolecule::bondUniqueId(const RWMolecule::BondType& b) const
{
  return b.molecule() == this ? findBondUniqueId(b.index()) : MaxIndex;
}

inline Index RWMolecule::bondCount() const
{
  return m_molecule.bondCount();
}

inline bool RWMolecule::removeBond(const RWMolecule::BondType& b)
{
  return b.molecule() == this ? removeBond(b.index()) : false;
}

inline bool RWMolecule::removeBond(Index atom1, Index atom2)
{
  return removeBond(bond(atom1, atom2).index());
}

inline bool RWMolecule::removeBond(const RWMolecule::AtomType& atom1,
                                   const RWMolecule::AtomType& atom2)
{
  if (atom1.molecule() != atom2.molecule() || atom1.molecule() != this)
    return false;
  return removeBond(bond(atom1.index(), atom2.index()).index());
}

inline Core::Array<RWMolecule::BondType> RWMolecule::bonds(
  const RWMolecule::AtomType& a) const
{
  return a.molecule() == this ? bonds(a.index()) : Core::Array<BondType>();
}

inline Core::Array<RWMolecule::BondType> RWMolecule::bonds(
  const Index& atomId) const
{
  Core::Array<RWMolecule::BondType> result;
  for (Index i = 0; i < m_molecule.m_bondPairs.size(); ++i)
    if (m_molecule.m_bondPairs[i].first == atomId ||
        m_molecule.m_bondPairs[i].second == atomId)
      result.push_back(BondType(const_cast<RWMolecule*>(this), i));
  return result;
}

inline const Core::Array<unsigned char>& RWMolecule::bondOrders() const
{
  return m_molecule.bondOrders();
}

inline unsigned char RWMolecule::bondOrder(Index bondId) const
{
  return m_molecule.bondOrder(bondId);
}

inline const Core::Array<std::pair<Index, Index>>& RWMolecule::bondPairs() const
{
  return m_molecule.bondPairs();
}

inline std::pair<Index, Index> RWMolecule::bondPair(Index bondId) const
{
  return m_molecule.bondPair(bondId);
}

inline void RWMolecule::beginMergeMode(const QString& undoName)
{
  m_interactive = true;
  m_undoStack.beginMacro(undoName);
}

inline void RWMolecule::endMergeMode()
{
  m_interactive = false;
  m_undoStack.endMacro();
}

inline void RWMolecule::setInteractive(bool b)
{
  m_interactive = b;
}

inline bool RWMolecule::isInteractive() const
{
  return m_interactive;
}

inline QUndoStack& RWMolecule::undoStack()
{
  return m_undoStack;
}

inline const QUndoStack& RWMolecule::undoStack() const
{
  return m_undoStack;
}

inline const Core::Array<Vector3>& RWMolecule::forceVectors() const
{
  return m_molecule.forceVectors();
}

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_RWMOLECULE_H
