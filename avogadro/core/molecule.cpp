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

Molecule::Molecule() : m_graphDirty(false)
{
}

Molecule::~Molecule()
{
}

size_t Molecule::size() const
{
  return m_atomicNumbers.size();
}

bool Molecule::isEmpty() const
{
  return m_atomicNumbers.empty();
}

void Molecule::setData(const std::string &name, const Variant &value)
{
  m_data.setValue(name, value);
}

Variant Molecule::data(const std::string &name) const
{
  return m_data.value(name);
}

void Molecule::setDataMap(const VariantMap &map)
{
  m_data = map;
}

const VariantMap &Molecule::dataMap() const
{
  return m_data;
}

VariantMap &Molecule::dataMap()
{
  return m_data;
}

std::vector<unsigned char>& Molecule::atomicNumbers()
{
  return m_atomicNumbers;
}

const std::vector<unsigned char>& Molecule::atomicNumbers() const
{
  return m_atomicNumbers;
}

std::vector<Vector2>& Molecule::atomPositions2d()
{
  return m_positions2d;
}

const std::vector<Vector2>& Molecule::atomPositions2d() const
{
  return m_positions2d;
}

std::vector<Vector3>& Molecule::atomPositions3d()
{
  return m_positions3d;
}

const std::vector<Vector3>& Molecule::atomPositions3d() const
{
  return m_positions3d;
}

std::vector<std::pair<size_t, size_t> >& Molecule::bondPairs()
{
  return m_bondPairs;
}

const std::vector<std::pair<size_t, size_t> >& Molecule::bondPairs() const
{
  return m_bondPairs;
}

std::vector<unsigned char>& Molecule::bondOrders()
{
  return m_bondOrders;
}

const std::vector<unsigned char>& Molecule::bondOrders() const
{
  return m_bondOrders;
}

Graph& Molecule::graph()
{
  updateGraph();
  return m_graph;
}

const Graph& Molecule::graph() const
{
  updateGraph();
  return m_graph;
}

Atom Molecule::addAtom(unsigned char atomicNumber)
{
  // Mark the graph as dirty.
  m_graphDirty = true;

  // Add the atomic number.
  m_atomicNumbers.push_back(atomicNumber);

  return Atom(this, m_atomicNumbers.size() - 1);
}

Atom Molecule::atom(size_t index) const
{
  assert(index < size());
  return Atom(const_cast<Molecule*>(this), index);
}

size_t Molecule::atomCount() const
{
  return m_atomicNumbers.size();
}

namespace {
// Make an std::pair where the lower index is always first in the pair. This
// offers us the guarantee that any given pair of atoms will always result in
// a pair that is the same no matter what the order of the atoms given.
std::pair<size_t, size_t> makeBondPair(const Atom &a, const Atom &b)
{
  return std::make_pair(a.index() < b.index() ? a.index() : b.index(),
                        a.index() < b.index() ? b.index() : a.index());
}
}

Bond Molecule::addBond(const Atom &a, const Atom &b, unsigned char bondOrder)
{
  assert(a.isValid() && a.molecule() == this);
  assert(b.isValid() && b.molecule() == this);

  m_graphDirty = true;
  m_bondPairs.push_back(makeBondPair(a, b));
  m_bondOrders.push_back(bondOrder);

  return Bond(this, m_bondPairs.size() - 1);
}

Bond Molecule::bond(size_t index) const
{
  assert(index < bondCount());

  return Bond(const_cast<Molecule*>(this), index);
}

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

size_t Molecule::bondCount() const
{
  return m_bondPairs.size();
}

std::string Molecule::formula() const
{
  // Adapted from chemkit:
  // A map of atomic symbols to their quantity.
  std::map<unsigned char, size_t> composition;
  for (std::vector<unsigned char>::const_iterator it = m_atomicNumbers.begin(),
       itEnd = m_atomicNumbers.end(); it != itEnd; ++it) {
    composition[*it]++;
  }

  std::stringstream result;
  std::map<unsigned char, size_t>::iterator iter;

  // Carbons first
  iter = composition.find(6);
  if (iter != composition.end()) {
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

// bond perception code ported from VTK's vtkSimpleBondPerceiver class
void Molecule::perceiveBonds()
{
  // check for coordinates
  if (m_positions3d.size() != atomCount())
    return;

  // the tolerance used in the comparisons
  double tolerance = 0.45;

  // cache atomic radii
  std::vector<double> radii(atomCount());
  for (size_t i = 0; i < radii.size(); i++)
    radii[i] = Elements::radiusCovalent(m_atomicNumbers[i]);

  // check for bonds
  for (size_t i = 0; i < atomCount(); i++) {
    Vector3 ipos = m_positions3d[i];
    for (size_t j = i + 1; j < atomCount(); j++) {
      double cutoff = radii[i] + radii[j] + tolerance;
      Vector3 jpos = m_positions3d[j];
      Vector3 diff = jpos - ipos;

      if (std::fabs(diff[0]) > cutoff ||
          std::fabs(diff[1]) > cutoff ||
          std::fabs(diff[2]) > cutoff ||
          (m_atomicNumbers[i] == 1 && m_atomicNumbers[j] == 1))
        continue;

      // check radius and add bond if needed
      double cutoffSq = cutoff * cutoff;
      double diffsq = diff.squaredNorm();
      if (diffsq < cutoffSq && diffsq > 0.1)
        addBond(atom(i), atom(j), 1);
    }
  }
}

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
