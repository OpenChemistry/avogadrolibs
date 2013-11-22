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
#include <vector>

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

/**
 * @class Molecule molecule.h <avogadro/core/molecule.h>
 * @brief The Molecule class represents a chemical molecule.
 */

class AVOGADROCORE_EXPORT Molecule
{
  friend class Atom;
  friend class Bond;
public:
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

  /** Returns the number of atoms in the molecule. */
  size_t size() const;

  /** Returns \c true if the molecule is empty (i.e. size() == \c 0). */
  bool isEmpty() const;

  /** Sets the data value with @p name to @p value. */
  virtual void setData(const std::string &name, const Variant &value);

  /** Returns the data value for @p name. */
  Variant data(const std::string &name) const;

  /**
   * Returns true if the molecule has data with the given key, false otherwise.
   */
  bool hasData(const std::string &name) const;

  /** Set the molecule's variant data to the entries in map. */
  virtual void setDataMap(const VariantMap &map);

  /** Return the molecule's variant data. */
  const VariantMap& dataMap() const;

  /**
   * Set the atomic number of atom @a atomIndex to @a number.
   * @return false if @a atomIndex is out of range.
   */
  bool setAtomicNumber(size_t atomIndex, unsigned char number);

  /** Returns a vector of atomic numbers for the atoms in the molecule. */
  const std::vector<unsigned char>& atomicNumbers() const;

  /**
   * Set the 2D position of atom @a atomIndex to @a pos.
   * @return false if @a atomIndex is out of range.
   */
  bool setAtomPosition2d(size_t atomIndex, const Vector2 &pos);

  /** Returns a vector of 2d atom positions for the atoms in the molecule. */
  const std::vector<Vector2>& atomPositions2d() const;

  /**
   * Set the 3D position of atom @a atomIndex to @a pos.
   * @return false if @a atomIndex is out of range.
   */
  bool setAtomPosition3d(size_t atomIndex, const Vector3 &pos);

  /** Returns a vector of 2d atom positions for the atoms in the molecule. */
  const std::vector<Vector3>& atomPositions3d() const;

  /** Returns a vector of pairs of atom indices of the bonds in the molecule. */
  const std::vector<std::pair<size_t, size_t> >& bondPairs() const;

  /**
   * Set the order of bond @a bondIndex to @a order.
   * @return false if @a bondIndex is out of range.
   */
  bool setBondOrder(size_t bondIndex, unsigned char order);

  /** Returns a vector of the bond orders for the bonds in the molecule. */
  const std::vector<unsigned char>& bondOrders() const;

  /** Returns the graph for the molecule. */
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
  virtual void setCustomElementMap(const CustomElementMap &map);
  /** @} */

  /**
   * @return True if custom elements exist in the molecule.
   * @note Custom element atomic numbers lie between CustomElementMin and
   * CustomElementMax.
   */
  bool hasCustomElements() const;

  /**  Adds an atom to the molecule. */
  virtual Atom addAtom(unsigned char atomicNumber);

  /**
   * @brief Remove the specified atom from the molecule.
   * @param index The index of the atom to be removed.
   * @return True on success, false if the atom was not found.
   */
  virtual bool removeAtom(size_t index);

  /**
   * @brief Remove the specified atom from the molecule.
   * @param atom The atom to be removed.
   * @return True on success, false if the atom was not found.
   * @overload
   */
  virtual bool removeAtom(const Core::Atom &atom);

  /**
   * Remove all atoms from the molecule.
   */
  virtual void clearAtoms();

  /**
   * @return the atom at @p index in the molecule.
   */
  Atom atom(size_t index) const;

  /**
   * @return The number of atoms in the molecule.
   */
  size_t atomCount() const;

  /**
   * @brief Get the number of atoms in the molecule that match atomicNumber.
   * @param atomicNumber The atomic number to match on.
   * @return The number of atoms with the supplied atomic number.
   */
  size_t atomCount(unsigned char atomicNumber) const;

  /** Adds a bond between atoms @p a and @p b. */
  virtual Bond addBond(const Atom &a, const Atom &b,
                       unsigned char bondOrder = 1);

  /**
   * @brief Remove the specified bond.
   * @param index The index of the bond to be removed.
   * @return True on success, false if the bond was not found.
   */
  virtual bool removeBond(size_t index);

  /**
   * @brief Remove the specified bond.
   * @param bond The bond to be removed.
   * @return True on success, false if the bond was not found.
   * @overload
   */
  virtual bool removeBond(const Core::Bond &bond);

  /**
   * @brief Remove the specified bond.
   * @param a One atom in the bond.
   * @param b The other atom in the bond.
   * @return True on success, false if the bond was not found.
   * @overload
   */
  virtual bool removeBond(const Core::Atom &a, const Core::Atom &b);

  /**
   * Remove all bonds from the molecule.
   */
  virtual void clearBonds();

  /** Returns the bond at @p index in the molecule. */
  Bond bond(size_t index) const;

  /** Returns the bond between atoms @p a and @p b. */
  Bond bond(const Atom &a, const Atom &b) const;

  /**
   * @brief Get all bonds to @p a.
   * @return A vector of bonds to the supplied atom @p a.
   */
  std::vector<Bond> bonds(const Atom &a);

  /** Returns the number of bonds in the molecule. */
  size_t bondCount() const;

  /**
   * @brief Add a mesh to the molecule.
   * @return The mesh object added to the molecule.
   */
  Mesh* addMesh();

  Mesh* mesh(size_t index);
  const Mesh* mesh(size_t index) const;

  size_t meshCount() const { return m_meshes.size(); }

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
  virtual void setUnitCell(UnitCell *uc);
  virtual UnitCell *unitCell() { return m_unitCell; }
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
  std::vector<unsigned char> m_atomicNumbers;
  std::vector<Vector2> m_positions2d;
  std::vector<Vector3> m_positions3d;
  std::vector<std::pair<size_t, size_t> > m_bondPairs;
  std::vector<unsigned char> m_bondOrders;

  std::vector<Mesh *> m_meshes;

  BasisSet *m_basisSet;
  UnitCell *m_unitCell;

  /** Update the graph to correspond to the current molecule. */
  void updateGraph() const;

  /** Internal methods for use by proxies. No bounds checking. @{ */
  virtual void setAtomicNumberInternal(size_t atomIndex, unsigned char number);
  virtual void setAtomPosition2dInternal(size_t atomIndex, const Vector2 &pos);
  virtual void setAtomPosition3dInternal(size_t atomIndex, const Vector3 &pos);
  virtual void setBondOrderInternal(size_t bondIndex, unsigned char order);
  /**@*/
};

inline bool Molecule::setAtomicNumber(size_t atomIndex, unsigned char number)
{
  if (atomIndex < atomCount()) {
    setAtomicNumberInternal(atomIndex, number);
    return true;
  }
  return false;
}

inline bool Molecule::setAtomPosition2d(size_t atomIndex, const Vector2 &pos)
{
  if (atomIndex < atomCount()) {
    setAtomPosition2dInternal(atomIndex, pos);
    return true;
  }
  return false;
}

inline bool Molecule::setAtomPosition3d(size_t atomIndex, const Vector3 &pos)
{
  if (atomIndex < atomCount()) {
    setAtomPosition3dInternal(atomIndex, pos);
    return true;
  }
  return false;
}

inline bool Molecule::setBondOrder(size_t bondIndex, unsigned char order)
{
  if (bondIndex < bondCount()) {
    setBondOrderInternal(bondIndex, order);
    return true;
  }
  return false;
}

inline size_t Molecule::atomCount() const
{
  return m_atomicNumbers.size();
}

inline size_t Molecule::bondCount() const
{
  return m_bondPairs.size();
}

inline void Molecule::setAtomicNumberInternal(size_t atomIndex,
                                              unsigned char number)
{
  m_atomicNumbers[atomIndex] = number;
}

inline void Molecule::setAtomPosition2dInternal(size_t atomIndex,
                                                const Vector2 &pos)
{
  if (atomIndex >= m_positions2d.size())
    m_positions2d.resize(atomIndex + 1);
  m_positions2d[atomIndex] = pos;
}

inline void Molecule::setAtomPosition3dInternal(size_t atomIndex,
                                                const Vector3 &pos)
{
  if (atomIndex >= m_positions3d.size())
    m_positions3d.resize(atomIndex + 1);
  m_positions3d[atomIndex] = pos;
}

inline void Molecule::setBondOrderInternal(size_t bondIndex,
                                           unsigned char order)
{
  m_bondOrders[bondIndex] = order;
}

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_MOLECULE_H
