/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011-2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_CORE_MOLECULE_H
#define AVOGADRO_CORE_MOLECULE_H

#include "avogadrocore.h"

#include <map>
#include <string>

#include "array.h"
#include "atom.h"
#include "bond.h"
#include "graph.h"
#include "variantmap.h"
#include "vector.h"

namespace Avogadro {
namespace Core {
class BasisSet;
class Mesh;
class UnitCell;

/** Concrete atom/bond proxy classes for Core::Molecule. @{ */
class Atom;
class Bond;
/** @} */

/**
 * @class Molecule molecule.h <avogadro/core/molecule.h>
 * @brief The Molecule class represents a chemical molecule.
 */
class AVOGADROCORE_EXPORT Molecule
{
public:
  /** Typedef for Atom class. */
  typedef Atom AtomType;

  /** Typedef for Bond class. */
  typedef Bond BondType;

  /** Type for custom element map. */
  typedef std::map<unsigned char, std::string> CustomElementMap;

  /** Creates a new, empty molecule. */
  Molecule();

  /** Copy constructor  */
  Molecule(const Molecule &other);

  /** Assignment operator */
  Molecule& operator=(const Molecule& other);

  /** Destroys the molecule object. */
  virtual ~Molecule();

  /** Sets the data value with @p name to @p value. */
  void setData(const std::string &name, const Variant &value);

  /** Returns the data value for @p name. */
  Variant data(const std::string &name) const;

  /**
   * Returns true if the molecule has data with the given key, false otherwise.
   */
  bool hasData(const std::string &name) const;

  /** Set the molecule's variant data to the entries in map. */
  void setDataMap(const VariantMap &map);

  /** Return the molecule's variant data. */
  const VariantMap& dataMap() const;

  /** \overload */
  VariantMap& dataMap();

  /** Returns a vector of atomic numbers for the atoms in the moleucle. */
  Array<unsigned char>& atomicNumbers();

  /** \overload */
  const Array<unsigned char>& atomicNumbers() const;

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

  /** Returns a vector of 2d atom positions for the atoms in the molecule. */
  const Array<Vector2>& atomPositions2d() const;

  /** \overload */
  Array<Vector2>& atomPositions2d();

  /**
   * Get the 2D position of a single atom.
   * @param atomId The index of the atom.
   * @return The position of the atom, or Vector3::Zero() if no position
   * information has been set.
   */
  Vector2 atomPosition2d(Index atomId) const;

  /**
   * Replace the current array of 2D atomic coordinates.
   * @param pos The new coordinate array. Must be of length atomCount().
   * @return True on success, false otherwise.
   */
  bool setAtomPositions2d(const Core::Array<Vector2> &pos);

  /**
   * Set the 2D position of a single atom.
   * @param atomId The index of the atom to modify.
   * @param pos The new position of the atom.
   * @return True on success, false otherwise.
   */
  bool setAtomPosition2d(Index atomId, const Vector2& pos);

  /** Returns a vector of 2d atom positions for the atoms in the molecule. */
  const Array<Vector3>& atomPositions3d() const;

  /** \overload */
  Array<Vector3>& atomPositions3d();

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

  /** Returns a vector of pairs of atom indices of the bonds in the molecule. */
  Array<std::pair<Index, Index> >& bondPairs();

  /** \overload */
  const Array<std::pair<Index, Index> >& bondPairs() const;

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
  bool setBondPairs(const Array<std::pair<Index, Index> > &pairs);

  /**
   * Set the bonded atoms for a bond.
   * @param bondId The bond to modify.
   * @param pair The new bond pair.
   * @return True on success, false otherwise.
   * @note If needed, @a pair will be modified to ensure that the first atom
   * index is less than the second.
   */
  bool setBondPair(Index bondId, const std::pair<Index, Index> &pair);

  /** Returns a vector of the bond orders for the bonds in the molecule. */
  Array<unsigned char>& bondOrders();

  /** \overload */
  const Array<unsigned char>& bondOrders() const;

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
  bool setBondOrders(const Array<unsigned char> &orders);

  /**
   * Set the order of a bond in the molecule.
   * @param bondId The bond's index.
   * @param order The new order of the bond.
   * @return True on success, false on failure.
   */
  bool setBondOrder(Index bondId, unsigned char order);

  /** Returns the graph for the molecule. */
  Graph& graph();

  /** \overload */
  const Graph& graph() const;

  /** A map of custom element atomic numbers to string identifiers. These ids
   * can be used to override the generic custom element names returned by the
   * Elements class, and should be somewhat meaningful to the user.
   *
   * @note Custom element atomic numbers lie between CustomElementMin and
   * CustomElementMax.
   * @sa Avogadro::QtGui::CustomElementDialog
   * @sa hasCustomElements
   * @{ */
  const CustomElementMap & customElementMap() const;
  void setCustomElementMap(const CustomElementMap &map);
  /** @} */

  /**
   * @return True if custom elements exist in the molecule.
   * @note Custom element atomic numbers lie between CustomElementMin and
   * CustomElementMax.
   */
  bool hasCustomElements() const;

  /**  Adds an atom to the molecule. */
  virtual AtomType addAtom(unsigned char atomicNumber);

  /**
   * @brief Remove the specified atom from the molecule.
   * @param index The index of the atom to be removed.
   * @return True on success, false if the atom was not found.
   */
  virtual bool removeAtom(Index index);

  /**
   * @brief Remove the specified atom from the molecule.
   * @param atom The atom to be removed.
   * @return True on success, false if the atom was not found.
   * @overload
   */
  virtual bool removeAtom(const AtomType &atom);

  /**
   * Remove all atoms from the molecule.
   */
  virtual void clearAtoms();

  /**
   * @return the atom at @p index in the molecule.
   */
  AtomType atom(Index index) const;

  /**
   * @return The number of atoms in the molecule.
   */
  Index atomCount() const;

  /**
   * @brief Get the number of atoms in the molecule that match atomicNumber.
   * @param atomicNumber The atomic number to match on.
   * @return The number of atoms with the supplied atomic number.
   */
  Index atomCount(unsigned char atomicNumber) const;

  /**
   * Create a new bond in the molecule.
   * @param atom1 The first atom in the bond.
   * @param atom2 The second order in the bond.
   * @param order The bond order.
   * @return The new bond object. Will be invalid if @a atom1 or @a atom2 does
   * not exist.
   * @{
   */
  virtual BondType addBond(Index atom1, Index atom2, unsigned char order = 1);
  virtual BondType addBond(const AtomType &atom1, const AtomType &atom2,
                           unsigned char order = 1);
  /** @} */

  /**
   * @brief Remove the specified bond.
   * @param index The index of the bond to be removed.
   * @return True on success, false if the bond was not found.
   */
  virtual bool removeBond(Index index);

  /**
   * @brief Remove the specified bond.
   * @param bond The bond to be removed.
   * @return True on success, false if the bond was not found.
   * @overload
   */
  virtual bool removeBond(const BondType &bond);

  /**
   * @brief Remove the specified bond.
   * @param atom1 One atom in the bond.
   * @param atom2 The other atom in the bond.
   * @return True on success, false if the bond was not found.
   * @overload
   * @{
   */
  virtual bool removeBond(Index atom1, Index atom2);
  virtual bool removeBond(const AtomType &atom1, const AtomType &atom2);
  /** @} */

  /**
   * Remove all bonds from the molecule.
   */
  virtual void clearBonds();

  /** Returns the bond at @p index in the molecule. */
  BondType bond(Index index) const;

  /** Returns the bond between atoms @p a and @p b. */
  BondType bond(const AtomType &a, const AtomType &b) const;

  /** Returns the bond between atomId1 and atomId2. */
  BondType bond(Index atomId1, Index atomId2) const;

  /**
   * @brief Get all bonds to @p a.
   * @return A vector of bonds to the supplied atom @p a.
   * @{
   */
  Array<BondType> bonds(const AtomType &a);
  Array<BondType> bonds(Index a);
  /** @} */

  /** Returns the number of bonds in the molecule. */
  Index bondCount() const;

  /**
   * @brief Add a mesh to the molecule.
   * @return The mesh object added to the molecule.
   */
  Mesh* addMesh();

  Mesh* mesh(Index index);
  const Mesh* mesh(Index index) const;

  Index meshCount() const { return static_cast<Index>(m_meshes.size()); }

  void clearMeshes();

  /**
   * Returns the chemical formula of the molecule
   * @todo This should eventually be an external algorithm, not a member of
   * Molecule.
   */
  std::string formula() const;

  /**
   * @return The mass of the molecule obtained by summing constituent atomic
   * masses.
   */
  double mass() const;

  /**
   * Set the basis set for the molecule, note that the molecule takes ownership
   * of the object.
   */
  void setBasisSet(BasisSet *basis) { m_basisSet = basis; }

  /**
   * Get the basis set (if present) for the molecule.
   */
  BasisSet * basisSet() { return m_basisSet; }

  /**
   * The unit cell for this molecule. May be NULL for non-periodic structures.
   * @{
   */
  void setUnitCell(UnitCell *uc);
  UnitCell *unitCell() { return m_unitCell; }
  const UnitCell *unitCell() const { return m_unitCell; }
  /** @} */

  /**
   * Perceives bonds in the molecule based on the 3D coordinates of the atoms.
   */
  void perceiveBondsSimple();

protected:
  mutable Graph m_graph; // A transformation of the molecule to a graph.
  mutable bool m_graphDirty; // Should the graph be rebuilt before returning it?
  VariantMap m_data;
  CustomElementMap m_customElementMap;
  Array<unsigned char> m_atomicNumbers;
  Array<Vector2> m_positions2d;
  Array<Vector3> m_positions3d;
  Array<std::pair<Index, Index> > m_bondPairs;
  Array<unsigned char> m_bondOrders;

  std::vector<Mesh *> m_meshes;

  BasisSet *m_basisSet;
  UnitCell *m_unitCell;

  /** Update the graph to correspond to the current molecule. */
  void updateGraph() const;
};

class AVOGADROCORE_EXPORT Atom : public AtomTemplate<Molecule>
{
public:
  Atom() : AtomTemplate<Molecule>() {}
  Atom(Molecule *m, Index i) : AtomTemplate<Molecule>(m, i) {}
};

class AVOGADROCORE_EXPORT Bond : public BondTemplate<Molecule>
{
public:
  Bond() : BondTemplate<Molecule>() {}
  Bond(Molecule *m, Index i) : BondTemplate<Molecule>(m, i) {}
};

inline unsigned char Molecule::atomicNumber(Index atomId) const
{
  return atomId < m_atomicNumbers.size() ? m_atomicNumbers[atomId]
                                           : InvalidElement;
}

inline bool Molecule::setAtomicNumbers(const Core::Array<unsigned char> &nums)
{
  if (nums.size() == atomCount()) {
    m_atomicNumbers = nums;
    return true;
  }
  return false;
}

inline bool Molecule::setAtomicNumber(Index atomId, unsigned char number)
{
  if (atomId < atomCount()) {
    m_atomicNumbers[atomId] = number;
    return true;
  }
  return false;
}

inline Vector2 Molecule::atomPosition2d(Index atomId) const
{
  return atomId < m_positions2d.size() ? m_positions2d[atomId] : Vector2();
}

inline bool Molecule::setAtomPositions2d(const Core::Array<Vector2> &pos)
{
  if (pos.size() == atomCount() || pos.size() == 0) {
    m_positions2d = pos;
    return true;
  }
  return false;
}

inline bool Molecule::setAtomPosition2d(Index atomId, const Vector2 &pos)
{
  if (atomId < atomCount()) {
    if (atomId >= m_positions2d.size())
      m_positions2d.resize(atomCount(), Vector2::Zero());
    m_positions2d[atomId] = pos;
    return true;
  }
  return false;
}

inline Vector3 Molecule::atomPosition3d(Index atomId) const
{
  return atomId < m_positions3d.size() ? m_positions3d[atomId] : Vector3();
}

inline bool Molecule::setAtomPositions3d(const Core::Array<Vector3> &pos)
{
  if (pos.size() == atomCount() || pos.size() == 0) {
    m_positions3d = pos;
    return true;
  }
  return false;
}

inline bool Molecule::setAtomPosition3d(Index atomId, const Vector3 &pos)
{
  if (atomId < atomCount()) {
    if (atomId >= m_positions3d.size())
      m_positions3d.resize(atomCount(), Vector3::Zero());
    m_positions3d[atomId] = pos;
    return true;
  }
  return false;
}

inline std::pair<Index, Index> Molecule::bondPair(Index bondId) const
{
  return bondId < bondCount() ? m_bondPairs[bondId]
                              : std::make_pair(MaxIndex, MaxIndex);
}

inline bool Molecule::setBondPairs(const Array<std::pair<Index, Index> > &pairs)
{
  if (pairs.size() == bondCount()) {
    m_bondPairs = pairs;
    return true;
  }
  return false;
}

inline bool Molecule::setBondPair(Index bondId,
                                  const std::pair<Index, Index> &pair)
{
  if (bondId < bondCount()) {
    m_bondPairs[bondId] = pair;
    return true;
  }
  return false;
}

inline unsigned char Molecule::bondOrder(Index bondId) const
{
  return bondId < m_bondOrders.size() ? m_bondOrders[bondId] : 0;
}

inline bool Molecule::setBondOrders(const Array<unsigned char> &orders)
{
  if (orders.size() == bondCount()) {
    m_bondOrders = orders;
    return true;
  }
  return false;
}

inline bool Molecule::setBondOrder(Index bondId, unsigned char order)
{
  if (bondId < bondCount()) {
    m_bondOrders[bondId] = order;
    return true;
  }
  return false;
}

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_MOLECULE_H
