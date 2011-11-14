/******************************************************************************

  This source file is part of the MolCore project.

  Copyright 2011 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "molecule.h"

#include <cassert>
#include <algorithm>

namespace MolCore {

// === Molecule ============================================================ //
/// \class Molecule
/// \brief The Molecule class represents a chemical molecule.

// --- Construction and Destruction ---------------------------------------- //
/// Creates a new, empty molecule.
Molecule::Molecule()
{
}

/// Destroys the molecule object.
Molecule::~Molecule()
{
}

// --- Properties ---------------------------------------------------------- //
/// Returns the number of atoms in the molecule.
size_t Molecule::size() const
{
  return m_graph.size();
}

/// Returns \c true if the molecule is empty (i.e. size() == \c 0).
bool Molecule::isEmpty() const
{
  return m_graph.isEmpty();
}

/// Sets the data value with \p name to \p value.
void Molecule::setData(const std::string &name, const Variant &value)
{
  m_data.setValue(name, value);
}

/// Returns the data value for \p name.
Variant Molecule::data(const std::string &name) const
{
  return m_data.value(name);
}

/// Returns a vector of atomic numbers for the atoms in the moleucle.
std::vector<unsigned char>& Molecule::atomicNumbers()
{
  return m_atomicNumbers;
}

/// \overload
const std::vector<unsigned char>& Molecule::atomicNumbers() const
{
  return m_atomicNumbers;
}

/// Returns a vector of pairs of atom indicies for the bonds in the
/// molecule.
std::vector<std::pair<size_t, size_t> >& Molecule::bondPairs()
{
  return m_bondPairs;
}

/// \overload
const std::vector<std::pair<size_t, size_t> >& Molecule::bondPairs() const
{
  return m_bondPairs;
}

/// Returns a vector containing the bond orders for the bonds in the
/// molecule.
std::vector<unsigned char>& Molecule::bondOrders()
{
  return m_bondOrders;
}

/// \overload
const std::vector<unsigned char>& Molecule::bondOrders() const
{
  return m_bondOrders;
}

/// Returns the graph for the molecule.
Graph& Molecule::graph()
{
  return m_graph;
}

/// \overload
const Graph& Molecule::graph() const
{
  return m_graph;
}

// --- Structure ----------------------------------------------------------- //
/// Adds an atom to the molecule.
Atom Molecule::addAtom(unsigned char atomicNumber)
{
  // add vertex to graph
  size_t index = m_graph.addVertex();

  // add atomic number
  m_atomicNumbers.push_back(atomicNumber);

  return Atom(this, index);
}

/// Returns the atom at \p index in the molecule.
Atom Molecule::atom(size_t index) const
{
  assert(index < size());

  return Atom(const_cast<Molecule*>(this), index);
}

/// Returns the number of atoms in the molecule.
size_t Molecule::atomCount() const
{
  return m_graph.size();
}

/// Adds a bond between atoms \p a and \p b.
Bond Molecule::addBond(const Atom &a, const Atom &b, unsigned char bondOrder)
{
  assert(a.isValid() && a.molecule() == this);
  assert(b.isValid() && b.molecule() == this);

  m_graph.addEdge(a.index(), b.index());
  m_bondPairs.push_back(std::make_pair(a.index(), b.index()));
  m_bondOrders.push_back(bondOrder);

  return Bond(this, m_bondPairs.size() - 1);
}

/// Returns the bond at \p index in the molecule.
Bond Molecule::bond(size_t index) const
{
  assert(index < bondCount());

  return Bond(const_cast<Molecule*>(this), index);
}

/// Returns the bond between atoms \p a and \p b.
Bond Molecule::bond(const Atom &a, const Atom &b) const
{
  assert(a.isValid() && a.molecule() == this);
  assert(b.isValid() && b.molecule() == this);

  std::pair<size_t, size_t> bondPair = std::make_pair(a.index(),
                                                      b.index());

  std::vector<std::pair<size_t, size_t> >::const_iterator iter =
    std::find(m_bondPairs.begin(), m_bondPairs.end(), bondPair);

  if (iter == m_bondPairs.end())
    return Bond();

  return Bond(const_cast<Molecule *>(this), iter - m_bondPairs.begin());
}

/// Returns the number of bonds in the molecule.
size_t Molecule::bondCount() const
{
  return m_bondPairs.size();
}

} // end MolCore namespace
