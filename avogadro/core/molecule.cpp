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

#include "molecule.h"

#include "elements.h"

#include <cassert>
#include <algorithm>

namespace Avogadro {
namespace Core {

// === Molecule ============================================================ //
/// \class Molecule
/// \brief The Molecule class represents a chemical molecule.

// --- Construction and Destruction ---------------------------------------- //
/// Creates a new, empty molecule.
Molecule::Molecule() : m_graphDirty(false)
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
  return m_atomicNumbers.size();
}

/// Returns \c true if the molecule is empty (i.e. size() == \c 0).
bool Molecule::isEmpty() const
{
  return m_atomicNumbers.empty();
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

/// Set the molecule's variant data to the entries in map.
void Molecule::setDataMap(const VariantMap &map)
{
  m_data = map;
}

/// Return the molecule's variant data.
const VariantMap &Molecule::dataMap() const
{
  return m_data;
}

/// \overload
VariantMap &Molecule::dataMap()
{
  return m_data;
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

/// Returns a vector of 2d atom positions for the atoms in the molecule.
std::vector<Vector2>& Molecule::atomPositions2d()
{
  return m_positions2d;
}

/// \overload
const std::vector<Vector2>& Molecule::atomPositions2d() const
{
  return m_positions2d;
}

/// Returns a vector of 2d atom positions for the atoms in the molecule.
std::vector<Vector3>& Molecule::atomPositions3d()
{
  return m_positions3d;
}

/// \overload
const std::vector<Vector3>& Molecule::atomPositions3d() const
{
  return m_positions3d;
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
  updateGraph();
  return m_graph;
}

/// \overload
const Graph& Molecule::graph() const
{
  updateGraph();
  return m_graph;
}

// --- Structure ----------------------------------------------------------- //
/// Adds an atom to the molecule.
Atom Molecule::addAtom(unsigned char atomicNumber)
{
  // Mark the graph as dirty.
  m_graphDirty = true;

  // add atomic number
  m_atomicNumbers.push_back(atomicNumber);

  return Atom(this, m_atomicNumbers.size() - 1);
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
  return m_atomicNumbers.size();
}

namespace {
std::pair<size_t, size_t> makeBondPair(const Atom &a, const Atom &b)
{
  return std::make_pair(a.index() < b.index() ? a.index() : b.index(),
                        a.index() < b.index() ? b.index() : a.index());
}
}

/// Adds a bond between atoms \p a and \p b.
Bond Molecule::addBond(const Atom &a, const Atom &b, unsigned char bondOrder)
{
  assert(a.isValid() && a.molecule() == this);
  assert(b.isValid() && b.molecule() == this);

  m_graphDirty = true;
  m_bondPairs.push_back(makeBondPair(a, b));
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

  std::pair<size_t, size_t> bondPair = makeBondPair(a, b);

  std::vector<std::pair<size_t, size_t> >::const_iterator iter =
    std::find(m_bondPairs.begin(), m_bondPairs.end(), bondPair);

  if (iter == m_bondPairs.end())
    return Bond();

  size_t index = static_cast<size_t>(std::distance(m_bondPairs.begin(), iter));

  return Bond(const_cast<Molecule *>(this), index);
}

std::vector<Bond> Molecule::bonds(const Atom &a)
{
  if (!a.isValid())
    return std::vector<Bond>();
  std::vector<Bond> atomBonds;
  size_t atomIndex = a.index();
  for (size_t i = 0; i < m_bondPairs.size(); ++i)
    if (m_bondPairs[i].first == atomIndex || m_bondPairs[i].second == atomIndex)
      atomBonds.push_back(Bond(this, i));
  return atomBonds;
}

/// Returns the number of bonds in the molecule.
size_t Molecule::bondCount() const
{
  return m_bondPairs.size();
}

/// Returns the chemical formula of the molecule
/// @todo This should eventually be an external algorithm, not a member of
/// Molecule.
std::string Molecule::formula() const
{
  // Adapted from chemkit:
  // a map of atomic symbols to their quantity
  std::map<unsigned char, size_t> composition;
  for (std::vector<unsigned char>::const_iterator it = m_atomicNumbers.begin(),
       itEnd = m_atomicNumbers.end(); it != itEnd; ++it) {
    composition[*it]++;
  }

  std::stringstream result;
  std::map<unsigned char, size_t>::iterator iter;

  // Carbons first
  iter = composition.find(6);
  if (iter != composition.end()){
    result << "C" << iter->second;
    composition.erase(iter);

    // If carbon is present, hydrogens are next.
    iter = composition.find(1);
    if (iter != composition.end()) {
      result << "H" << iter->second;
      composition.erase(iter);
    }
  }

  // The rest:
  iter = composition.begin();
  while (iter != composition.end())
    result << Elements::symbol(iter->first) << iter->second, ++iter;

  return result.str();
}

/// Update the graph to correspond to the current molecule.
void Molecule::updateGraph() const
{
  if (!m_graphDirty)
    return;
  m_graphDirty = false;
  m_graph.clear();
  m_graph.setSize(atomCount());
  for (std::vector<std::pair<size_t, size_t> >::const_iterator it = m_bondPairs.begin();
       it != m_bondPairs.end(); ++it) {
    m_graph.addEdge(it->first, it->second);
  }
}

} // end Core namespace
} // end Avogadro namespace
