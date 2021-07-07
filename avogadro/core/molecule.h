/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_MOLECULE_H
#define AVOGADRO_CORE_MOLECULE_H

#include "avogadrocore.h"

#include <map>
#include <string>

#include "array.h"
#include "bond.h"
#include "elements.h"
#include "graph.h"
#include "variantmap.h"
#include "vector.h"

namespace Avogadro {
namespace Core {
class BasisSet;
class Cube;
class Mesh;
class Residue;
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
  Molecule(const Molecule& other);

  /** Move constructor */
  Molecule(Molecule&& other) noexcept;

  /** Assignment operator */
  Molecule& operator=(const Molecule& other);

  /** Move assignment operator */
  Molecule& operator=(Molecule&& other) noexcept;

  /** Destroys the molecule object. */
  virtual ~Molecule();

  /** Sets the data value with @p name to @p value. */
  void setData(const std::string& name, const Variant& value);

  /** Returns the data value for @p name. */
  Variant data(const std::string& name) const;

  /**
   * Returns true if the molecule has data with the given key, false otherwise.
   */
  bool hasData(const std::string& name) const;

  /** Set the molecule's variant data to the entries in map. */
  void setDataMap(const VariantMap& map);

  /** Return the molecule's variant data. */
  const VariantMap& dataMap() const;

  /** \overload */
  VariantMap& dataMap();

  /** Returns a vector of atomic numbers for the atoms in the molecule. */
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
  bool setAtomicNumbers(const Core::Array<unsigned char>& nums);

  /**
   * Set the atomic number of a single atom.
   * @param atomId The index of the atom to modify.
   * @param atomicNumber The new atomic number.
   * @return True on success, false otherwise.
   */
  bool setAtomicNumber(Index atomId, unsigned char atomicNumber);

  /** Returns a vector of hybridizations for the atoms in the molecule. */
  Array<AtomHybridization>& hybridizations();

  /** \overload */
  const Array<AtomHybridization>& hybridizations() const;

  /**
   * Get the hybridization for the requested atom.
   * @param atomId The index of the atom.
   * @return The hybridization of the atom indexed at @a atomId, or
   * 0 if @a atomId is invalid.
   */
  AtomHybridization hybridization(Index atomId) const;

  /**
   * Replace the current array of hybridizations.
   * @param hybs The new hybridization array. Must be of length atomCount().
   * @return True on success, false otherwise.
   */
  bool setHybridizations(const Core::Array<AtomHybridization>& hybs);

  /**
   * Set the hybridization of a single atom.
   * @param atomId The index of the atom to modify.
   * @param hybridization The new hybridization.
   * @return True on success, false otherwise.
   */
  bool setHybridization(Index atomId, AtomHybridization hybridization);

  /** Returns a vector of formal charges for the atoms in the molecule. */
  Array<signed char>& formalCharges();

  /** \overload */
  const Array<signed char>& formalCharges() const;

  /**
   * Get the formal charge for the requested atom.
   * @param atomId The index of the atom.
   * @return The formal charge of the atom indexed at @a atomId, or
   * 0 if @a atomId is invalid.
   */
  signed char formalCharge(Index atomId) const;

  /**
   * Replace the current array of formal charges.
   * @param charges The new formal charge array. Must be of length atomCount().
   * @return True on success, false otherwise.
   */
  bool setFormalCharges(const Core::Array<signed char>& charges);

  /**
   * Set the formal charge of a single atom.
   * @param atomId The index of the atom to modify.
   * @param charge The new formal charge.
   * @return True on success, false otherwise.
   */
  bool setFormalCharge(Index atomId, signed char charge);

  /** Returns a vector of colors for the atoms in the moleucle. */
  Array<Vector3ub>& colors();

  /** \overload */
  const Array<Vector3ub>& colors() const;

  /**
   * Get the color for the requested atom.
   * @param atomId The index of the atom.
   * @return The color of the atom indexed at @a atomId, or
   * (0,0,0) if @a atomId is invalid. If no color is set for the
   * given atomId, the default color for the atomic number of
   * the atomId is returned.
   */
  Vector3ub color(Index atomId) const;

  /**
   * Replace the current array of colors.
   * @param colors The new color array. Must be of length atomCount().
   * @return True on success, false otherwise.
   */
  bool setColors(const Core::Array<Vector3ub>& colors);

  /**
   * Set the color of a single atom.
   * @param atomId The index of the atom to modify.
   * @param color The new color.
   * @return True on success, false otherwise.
   */
  bool setColor(Index atomId, Vector3ub color);

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
  bool setAtomPositions2d(const Core::Array<Vector2>& pos);

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
  bool setAtomPositions3d(const Core::Array<Vector3>& pos);

  /**
   * Set the 3D position of a single atom.
   * @param atomId The index of the atom to modify.
   * @param pos The new position of the atom.
   * @return True on success, false otherwise.
   */
  bool setAtomPosition3d(Index atomId, const Vector3& pos);

  /**
   * Set whether the specified atom is selected or not.
   */
  void setAtomSelected(Index atomId, bool selected);

  /**
   * Query whether the supplied atom index has been selected.
   */
  bool atomSelected(Index atomId) const;

  /** Returns whether the selection is empty or not */
  bool isSelectionEmpty() const;

  /** Returns a vector of pairs of atom indices of the bonds in the molecule. */
  Array<std::pair<Index, Index>>& bondPairs();

  /** \overload */
  const Array<std::pair<Index, Index>>& bondPairs() const;

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
  bool setBondPairs(const Array<std::pair<Index, Index>>& pairs);

  /**
   * Set the bonded atoms for a bond.
   * @param bondId The bond to modify.
   * @param pair The new bond pair.
   * @return True on success, false otherwise.
   * @note If needed, @a pair will be modified to ensure that the first atom
   * index is less than the second.
   */
  bool setBondPair(Index bondId, const std::pair<Index, Index>& pair);

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
  bool setBondOrders(const Array<unsigned char>& orders);

  /**
   * Set the order of a bond in the molecule.
   * @param bondId The bond's index.
   * @param order The new order of the bond.
   * @return True on success, false on failure.
   */
  bool setBondOrder(Index bondId, unsigned char order) const;

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
  const CustomElementMap& customElementMap() const;
  void setCustomElementMap(const CustomElementMap& map);
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
  virtual bool removeAtom(const AtomType& atom);

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
   * @param atom2 The second atom in the bond.
   * @param order The bond order.
   * @return The new bond object. Will be invalid if @a atom1 or @a atom2 does
   * not exist.
   * @{
   */
  virtual BondType addBond(Index atom1, Index atom2, unsigned char order = 1);
  virtual BondType addBond(const AtomType& atom1, const AtomType& atom2,
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
  virtual bool removeBond(const BondType& bond);

  /**
   * @brief Remove the specified bond.
   * @param atom1 One atom in the bond.
   * @param atom2 The other atom in the bond.
   * @return True on success, false if the bond was not found.
   * @overload
   * @{
   */
  virtual bool removeBond(Index atom1, Index atom2);
  virtual bool removeBond(const AtomType& atom1, const AtomType& atom2);
  /** @} */

  /**
   * Remove all bonds from the molecule.
   */
  virtual void clearBonds();

  /** Returns the bond at @p index in the molecule. */
  BondType bond(Index index) const;

  /** Returns the bond between atoms @p a and @p b. */
  BondType bond(const AtomType& a, const AtomType& b) const;

  /** Returns the bond between atomId1 and atomId2. */
  BondType bond(Index atomId1, Index atomId2) const;

  /**
   * @brief Get all bonds to @p a.
   * @return A vector of bonds to the supplied atom @p a.
   * @{
   */
  Array<BondType> bonds(const AtomType& a);
  Array<BondType> bonds(Index a);
  Array<const BondType*> bonds(Index a) const;
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
   * @brief Add a cube to the molecule.
   * @return The cube object added to the molecule.
   */
  Cube* addCube();

  Cube* cube(Index index);
  const Cube* cube(Index index) const;

  Index cubeCount() const { return static_cast<Index>(m_cubes.size()); }

  void clearCubes();

  /**
   * @brief Get the cubes vector set (if present) for the molecule.
   * @return The cube vector for the molecule
   */
  std::vector<Cube*> cubes() { return m_cubes; }
  const std::vector<Cube*> cubes() const { return m_cubes; }

  /**
   * Returns the chemical formula of the molecule.
   * @param delimiter Delimiter to insert between tokens, defaults to none.
   * @param showCountsOver Show atom counts above this (defaults to 1).
   */
  std::string formula(const std::string& delimiter = "",
                      int showCountsOver = 1) const;

  /**
   * @return The mass of the molecule obtained by summing constituent atomic
   * masses.
   */
  double mass() const;

  /**
   * @return The center of geometry of the molecule obtained by summing the
   * coordinates of the atoms.
   */
  Vector3 centerOfGeometry() const;

  /**
   * @return The center of mass of the molecule obtained by summing the
   * coordinates of the atoms weighted by mass.
   */
  Vector3 centerOfMass() const;

  /**
   * @return The minimum radius of a sphere centered on centerOfGeometry
   * containing all the centers of the atoms.
   */
  double radius() const;

  /**
   * @return The (centroid, normal vector) pair of the best-fit plane of
   * the atoms of the molecule.
   */
  std::pair<Vector3, Vector3> bestFitPlane() const;

  /**
   * @return The normal vector of the best-fit plane of some specific atoms.
   */
  static std::pair<Vector3, Vector3> bestFitPlane(const Array<Vector3>& pos);

  /**
   * Set the basis set for the molecule, note that the molecule takes ownership
   * of the object.
   */
  void setBasisSet(BasisSet* basis) { m_basisSet = basis; }

  /**
   * Get the basis set (if present) for the molecule.
   */
  BasisSet* basisSet() { return m_basisSet; }
  const BasisSet* basisSet() const { return m_basisSet; }

  /**
   * The unit cell for this molecule. May be nullptr for non-periodic
   * structures.
   * @{
   */
  void setUnitCell(UnitCell* uc);
  UnitCell* unitCell() { return m_unitCell; }
  const UnitCell* unitCell() const { return m_unitCell; }
  /** @} */

  /**
   * The space group for this molecule. It is updated after every
   * space group operation.
   * @{
   */
  void setHallNumber(unsigned short hallNumber) { m_hallNumber = hallNumber; }
  unsigned short hallNumber() const { return m_hallNumber; }
  /** @} */

  Array<double> vibrationFrequencies() const;
  void setVibrationFrequencies(const Array<double>& freq);
  Array<double> vibrationIntensities() const;
  void setVibrationIntensities(const Array<double>& intensities);
  Array<Vector3> vibrationLx(int mode) const;
  void setVibrationLx(const Array<Array<Vector3>>& lx);

  /**
   * Perceives bonds in the molecule based on the 3D coordinates of the atoms.
   *  atoms are considered bonded if within the sum of radii
   *  plus a small @p tolerance.
   * @param tolerance The calculation tolerance.
   * @param minDistance = atoms closer than the square of this are ignored
   */
  void perceiveBondsSimple(const double tolerance = 0.45,
                           const double minDistance = 0.32);

  /**
   * Perceives bonds in the molecule based on preset residue data.
   */
  void perceiveBondsFromResidueData();

  int coordinate3dCount();
  bool setCoordinate3d(int coord);
  Array<Vector3> coordinate3d(int index) const;
  bool setCoordinate3d(const Array<Vector3>& coords, int index);

  /**
   * Timestep property is used when molecular dynamics trajectories are read
   */
  bool setTimeStep(double timestep, int index);
  double timeStep(int index, bool& status);

  /** @return a vector of forces for the atoms in the molecule. */
  const Array<Vector3>& forceVectors() const;

  /** \overload */
  Array<Vector3>& forceVectors();

  /**
   * Get the force of a single atom.
   * @param atomId The index of the atom.
   * @return The force vector of the atom, or Vector3::Zero() if no force
   * information has been set.
   */
  Vector3 forceVector(Index atomId) const;

  /**
   * Replace the current array of force vectors.
   * @param forces The new coordinate array. Must be of length atomCount().
   * @return True on success, false otherwise.
   */
  bool setForceVectors(const Core::Array<Vector3>& forces);

  /**
   * Set the 3D position of a single atom.
   * @param atomId The index of the atom to modify.
   * @param force The new position of the atom.
   * @return True on success, false otherwise.
   */
  bool setForceVector(Index atomId, const Vector3& force);

  Residue& addResidue(std::string& name, Index& number, char& id);
  void addResidue(Residue& residue);
  Residue& residue(Index index);

  Array<Residue>& residues() { return m_residues; }
  const Array<Residue>& residues() const { return m_residues; }

protected:
  mutable Graph m_graph;     // A transformation of the molecule to a graph.
  mutable bool m_graphDirty; // Should the graph be rebuilt before returning it?
  size_t m_historyID;        // count the changes done
  VariantMap m_data;
  CustomElementMap m_customElementMap;
  Array<unsigned char> m_atomicNumbers;
  Array<Vector2> m_positions2d;
  Array<Vector3> m_positions3d;
  Array<Array<Vector3>> m_coordinates3d; // Used for conformers/trajectories.
  Array<double> m_timesteps;
  Array<AtomHybridization> m_hybridizations;
  Array<signed char> m_formalCharges;
  Array<Vector3> m_forceVectors;
  Array<Vector3ub> m_colors;

  // Vibration data if available.
  Array<double> m_vibrationFrequencies;
  Array<double> m_vibrationIntensities;
  Array<Array<Vector3>> m_vibrationLx;

  Array<std::pair<Index, Index>> m_bondPairs;
  mutable Array<unsigned char> m_bondOrders;

  // Array declaring whether atoms are selected or not.
  std::vector<bool> m_selectedAtoms;

  std::vector<Mesh*> m_meshes;
  std::vector<Cube*> m_cubes;

  BasisSet* m_basisSet;
  UnitCell* m_unitCell;
  Array<Residue> m_residues;

  // This will be stored from the last space group operation
  unsigned short m_hallNumber = 0;

  /** Update the graph to correspond to the current molecule. */
  void updateGraph() const;
};

class AVOGADROCORE_EXPORT Atom : public AtomTemplate<Molecule>
{
public:
  Atom() : AtomTemplate<Molecule>() {}
  Atom(Molecule* m, Index i) : AtomTemplate<Molecule>(m, i) {}
};

class AVOGADROCORE_EXPORT Bond : public BondTemplate<Molecule>
{
public:
  Bond() : BondTemplate<Molecule>() {}
  Bond(Molecule* m, Index i) : BondTemplate<Molecule>(m, i) {}
};

inline unsigned char Molecule::atomicNumber(Index atomId) const
{
  return atomId < m_atomicNumbers.size() ? m_atomicNumbers[atomId]
                                         : InvalidElement;
}

inline bool Molecule::setAtomicNumbers(const Core::Array<unsigned char>& nums)
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

inline AtomHybridization Molecule::hybridization(Index atomId) const
{
  AtomHybridization hyb = HybridizationUnknown;
  if (atomId < m_hybridizations.size())
    return m_hybridizations[atomId];

  return hyb;
}

inline bool Molecule::setHybridizations(
  const Core::Array<AtomHybridization>& hybs)
{
  if (hybs.size() == atomCount()) {
    m_hybridizations = hybs;
    return true;
  }
  return false;
}

inline bool Molecule::setHybridization(Index atomId, AtomHybridization hyb)
{
  if (atomId < atomCount()) {
    if (atomId >= m_hybridizations.size())
      m_hybridizations.resize(atomCount(), HybridizationUnknown);
    m_hybridizations[atomId] = hyb;
    return true;
  }
  return false;
}

inline signed char Molecule::formalCharge(Index atomId) const
{
  return atomId < m_formalCharges.size() ? m_formalCharges[atomId] : 0;
}

inline bool Molecule::setFormalCharges(const Core::Array<signed char>& charges)
{
  if (charges.size() == atomCount()) {
    m_formalCharges = charges;
    return true;
  }
  return false;
}

inline bool Molecule::setFormalCharge(Index atomId, signed char charge)
{
  if (atomId < atomCount()) {
    if (atomId >= m_formalCharges.size())
      m_formalCharges.resize(atomCount(), 0);
    m_formalCharges[atomId] = charge;
    return true;
  }
  return false;
}

inline Vector3ub Molecule::color(Index atomId) const
{
  if (atomId >= atomCount())
    return Vector3ub(0, 0, 0);

  if (atomId < m_colors.size())
    return m_colors[atomId];

  return Vector3ub(Elements::color(atomicNumber(atomId)));
}

inline bool Molecule::setColors(const Core::Array<Vector3ub>& colors)
{
  if (colors.size() == atomCount()) {
    m_colors = colors;
    return true;
  }
  return false;
}

inline bool Molecule::setColor(Index atomId, Vector3ub color)
{
  if (atomId < atomCount()) {
    if (atomId >= m_colors.size()) {
      for (Index i = m_colors.size(); i < atomCount(); ++i) {
        m_colors.push_back(Vector3ub(Elements::color(atomicNumber(i))));
      }
    }
    m_colors[atomId] = color;
    return true;
  }
  return false;
}

inline Vector2 Molecule::atomPosition2d(Index atomId) const
{
  return atomId < m_positions2d.size() ? m_positions2d[atomId] : Vector2();
}

inline bool Molecule::setAtomPositions2d(const Core::Array<Vector2>& pos)
{
  if (pos.size() == atomCount() || pos.size() == 0) {
    m_positions2d = pos;
    return true;
  }
  return false;
}

inline bool Molecule::setAtomPosition2d(Index atomId, const Vector2& pos)
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

inline bool Molecule::setAtomPositions3d(const Core::Array<Vector3>& pos)
{
  if (pos.size() == atomCount() || pos.size() == 0) {
    m_positions3d = pos;
    return true;
  }
  return false;
}

inline bool Molecule::setAtomPosition3d(Index atomId, const Vector3& pos)
{
  if (atomId < atomCount()) {
    if (atomId >= m_positions3d.size())
      m_positions3d.resize(atomCount(), Vector3::Zero());
    m_positions3d[atomId] = pos;
    return true;
  }
  return false;
}

inline void Molecule::setAtomSelected(Index atomId, bool selected)
{
  if (atomId < atomCount()) {
    if (atomId >= m_selectedAtoms.size())
      m_selectedAtoms.resize(atomCount(), false);
    m_selectedAtoms[atomId] = selected;
  }
}

inline bool Molecule::atomSelected(Index atomId) const
{
  return atomId < m_selectedAtoms.size() ? m_selectedAtoms[atomId] : false;
}

inline bool Molecule::isSelectionEmpty() const
{
  for (Index i = 0; i < m_selectedAtoms.size(); ++i) {
    if (m_selectedAtoms[i])
      return false;
  }
  return true;
}

inline std::pair<Index, Index> Molecule::bondPair(Index bondId) const
{
  return bondId < bondCount() ? m_bondPairs[bondId]
                              : std::make_pair(MaxIndex, MaxIndex);
}

inline bool Molecule::setBondPairs(const Array<std::pair<Index, Index>>& pairs)
{
  if (pairs.size() == bondCount()) {
    m_bondPairs = pairs;
    return true;
  }
  return false;
}

inline bool Molecule::setBondPair(Index bondId,
                                  const std::pair<Index, Index>& pair)
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

inline bool Molecule::setBondOrders(const Array<unsigned char>& orders)
{
  if (orders.size() == bondCount()) {
    m_bondOrders = orders;
    return true;
  }
  return false;
}

inline bool Molecule::setBondOrder(Index bondId, unsigned char order) const
{
  if (bondId < bondCount()) {
    m_bondOrders[bondId] = order;
    return true;
  }
  return false;
}

inline Vector3 Molecule::forceVector(Index atomId) const
{
  return atomId < m_forceVectors.size() ? m_forceVectors[atomId] : Vector3();
}

inline bool Molecule::setForceVectors(const Core::Array<Vector3>& forces)
{
  if (forces.size() == atomCount() || forces.size() == 0) {
    m_forceVectors = forces;
    return true;
  }
  return false;
}

inline bool Molecule::setForceVector(Index atomId, const Vector3& force)
{
  if (atomId < atomCount()) {
    if (atomId >= m_forceVectors.size())
      m_forceVectors.resize(atomCount(), Vector3::Zero());
    m_forceVectors[atomId] = force;
    return true;
  }
  return false;
}

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_MOLECULE_H
