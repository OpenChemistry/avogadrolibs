/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_MOLECULEINFO_H
#define AVOGADRO_CORE_MOLECULEINFO_H

#include "avogadrocore.h"

#include "array.h"
#include "graph.h"

#include <map>
#include <utility>

namespace Avogadro {
namespace Core {

class AVOGADROCORE_EXPORT MoleculeGraph
{
public:
  MoleculeGraph();
  MoleculeGraph(const MoleculeGraph& other);
  MoleculeGraph(MoleculeGraph&& other) noexcept;
  MoleculeGraph operator=(const MoleculeGraph& other);
  MoleculeGraph operator=(MoleculeGraph&& other) noexcept;
  ~MoleculeGraph();

  // counts
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
  /** Returns the number of bonds in the molecule. */
  Index bondCount() const;

  // getters and setters
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

  /** Returns a vector of pairs of atom indices of the bonds in the molecule. */
  Array<std::pair<Index, Index>>& bondPairs();
  /** \overload */
  const Array<std::pair<Index, Index>>& bondPairs() const;

  /** Returns a vector of the bond orders for the bonds in the molecule. */
  Array<unsigned char>& bondOrders();
  /** \overload */
  const Array<unsigned char>& bondOrders() const;

  /** Returns the graph for the molecule. */
  Graph& graph();
  /** \overload */
  const Graph& graph() const;

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
  bool setBondOrder(Index bondId, unsigned char order);
  /**
   * @return True if custom elements exist in the molecule.
   * @note Custom element atomic numbers lie between CustomElementMin and
   * CustomElementMax.
   */
  bool hasCustomElements() const;

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
   * Get the order of a bond.
   * @param bondId The id of the bond.
   * @return The bond order.
   */
  unsigned char bondOrder(Index bondId) const;
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
   * @return a map of components and count.
   */
  std::map<unsigned char, size_t> composition() const;

  // search if the bond exists, if not returns maxSize
  Index findBond(Index atomId1, Index atomId2) const;

  void setGraphDirty(bool dirty) const;

  Array<std::pair<Index, Index>> getBonds(Index index) const;
  Array<unsigned char> getOrders(Index index) const;

  void addBonds(const Array<std::pair<Index, Index>>& bonds,
                const Array<unsigned char>& orders);

  // chenge the bond index position
  void swapBond(Index a, Index b);
  // channge the Atom index position
  void swapAtom(Index a, Index b);

protected:
  // update base info first, next derivated
  bool addAtom(unsigned char number);
  bool addBond(Index atom1, Index atom2, unsigned char order = 1);

  bool removeAtom(Index index);
  bool removeBond(Index index);
  bool removeBonds(Index atom);

  void clearAtoms();
  void clearBonds();

private:
  /** Update the graph to correspond to the current molecule. */
  void updateGraph() const;
  // the old atom is dirty and needs a update
  void rebondBond(Index newIndex, Index oldIndex);

  mutable Graph m_graph;     // A transformation of the molecule to a graph.
  mutable bool m_graphDirty; // Should the graph be rebuilt?
  // edge information
  Array<std::pair<Index, Index>> m_bondPairs;
  Array<unsigned char> m_bondOrders;
  // vertex information
  Array<unsigned char> m_atomicNumbers;
};

} // namespace Core
} // namespace Avogadro

#endif
