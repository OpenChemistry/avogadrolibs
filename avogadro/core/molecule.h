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

#include <string>
#include <vector>

#include "atom.h"
#include "bond.h"
#include "graph.h"
#include "variantmap.h"
#include "vector.h"

namespace Avogadro {
namespace Core {

/**
 * @class Molecule molecule.h <avogadro/core/molecule.h>
 * @brief The Molecule class represents a chemical molecule.
 */

class AVOGADROCORE_EXPORT Molecule
{
public:
  /** Creates a new, empty molecule. */
  Molecule();

  /** Destroys the molecule object. */
  virtual ~Molecule();

  /** Returns the number of atoms in the molecule. */
  size_t size() const;

  /** Returns \c true if the molecule is empty (i.e. size() == \c 0). */
  bool isEmpty() const;

  /** Sets the data value with @p name to @p value. */
  void setData(const std::string &name, const Variant &value);

  /** Returns the data value for @p name. */
  Variant data(const std::string &name) const;

  /** Set the molecule's variant data to the entries in map. */
  void setDataMap(const VariantMap &map);

  /** Return the molecule's variant data. */
  const VariantMap& dataMap() const;

  /** \overload */
  VariantMap& dataMap();

  /** Returns a vector of atomic numbers for the atoms in the moleucle. */
  std::vector<unsigned char>& atomicNumbers();

  /** \overload */
  const std::vector<unsigned char>& atomicNumbers() const;

  /** Returns a vector of 2d atom positions for the atoms in the molecule. */
  const std::vector<Vector2>& atomPositions2d() const;

  /** \overload */
  std::vector<Vector2>& atomPositions2d();

  /** Returns a vector of 2d atom positions for the atoms in the molecule. */
  const std::vector<Vector3>& atomPositions3d() const;

  /** \overload */
  std::vector<Vector3>& atomPositions3d();

  /** Returns a vector of pairs of atom indices of the bonds in the molecule. */
  std::vector<std::pair<size_t, size_t> >& bondPairs();

  /** \overload */
  const std::vector<std::pair<size_t, size_t> >& bondPairs() const;

  /** Returns a vector of the bond orders for the bonds in the molecule. */
  std::vector<unsigned char>& bondOrders();

  /** \overload */
  const std::vector<unsigned char>& bondOrders() const;

  /** Returns the graph for the molecule. */
  Graph& graph();

  /** \overload */
  const Graph& graph() const;

  /**  Adds an atom to the molecule. */
  Atom addAtom(unsigned char atomicNumber);

  /**  Returns the atom at @p index in the molecule. */
  Atom atom(size_t index) const;

  /** Returns the number of atoms in the molecule. */
  size_t atomCount() const;

  /** Adds a bond between atoms @p a and @p b. */
  Bond addBond(const Atom &a, const Atom &b, unsigned char bondOrder = 1);

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
   * Returns the chemical formula of the molecule
   * \todo This should eventually be an external algorithm, not a member of
   * Molecule.
   */
  std::string formula() const;

protected:
  mutable Graph m_graph; // A transformation of the molecule to a graph.
  mutable bool m_graphDirty; // Should the graph be rebuilt before returning it?
  VariantMap m_data;
  std::vector<unsigned char> m_atomicNumbers;
  std::vector<Vector2> m_positions2d;
  std::vector<Vector3> m_positions3d;
  std::vector<std::pair<size_t, size_t> > m_bondPairs;
  std::vector<unsigned char> m_bondOrders;

  /** Update the graph to correspond to the current molecule. */
  void updateGraph() const;
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_MOLECULE_H
