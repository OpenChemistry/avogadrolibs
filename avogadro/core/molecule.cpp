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

#include "basisset.h"
#include "color3f.h"
#include "elements.h"
#include "mesh.h"
#include "unitcell.h"

#include <cassert>
#include <algorithm>

namespace Avogadro {
namespace Core {

Molecule::Molecule() : m_graphDirty(false), m_basisSet(NULL), m_unitCell(NULL)
{
}

Molecule::Molecule(const Molecule &other)
  : m_graphDirty(true),
    m_data(other.m_data),
    m_customElementMap(other.m_customElementMap),
    m_atomicNumbers(other.atomicNumbers()),
    m_positions2d(other.m_positions2d),
    m_positions3d(other.m_positions3d),
    m_bondPairs(other.m_bondPairs),
    m_bondOrders(other.m_bondOrders),
    m_basisSet(NULL),
    m_unitCell(other.m_unitCell ? new UnitCell(*other.m_unitCell) : NULL)
{
  // Copy over any meshes
  for(size_t i=0; i< other.meshCount(); i++) {
    Mesh *m = addMesh();
    *m = *other.mesh(i);
  }
}

Molecule& Molecule::operator=(const Molecule& other)
{
  if (this != &other) {
    m_graphDirty = true;
    m_customElementMap = other.m_customElementMap;
    m_basisSet = NULL;
    m_unitCell = other.m_unitCell ? new UnitCell(*other.m_unitCell) : NULL;
    m_data = other.m_data;
    m_atomicNumbers = other.m_atomicNumbers;
    m_positions2d = other.m_positions2d;
    m_positions3d = other.m_positions3d;
    m_bondPairs = other.m_bondPairs;
    m_bondOrders = other.m_bondOrders;

    clearMeshes();

    // Copy over any meshes
    for(size_t i=0; i< other.meshCount(); i++) {
      Mesh *m = addMesh();
      *m = *other.mesh(i);
    }
  }

  return *this;
}

Molecule::~Molecule()
{
  delete m_basisSet;
  delete m_unitCell;
  clearMeshes();
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

bool Molecule::hasData(const std::string &name) const
{
  return m_data.hasValue(name);
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

const Molecule::CustomElementMap &Molecule::customElementMap() const
{
  return m_customElementMap;
}

void Molecule::setCustomElementMap(const Molecule::CustomElementMap &map)
{
  m_customElementMap = map;
}

bool Molecule::hasCustomElements() const
{
  for (std::vector<unsigned char>::const_iterator
       it = m_atomicNumbers.begin(), itEnd = m_atomicNumbers.end();
       it != itEnd; ++it) {
    if (Core::isCustomElement(*it))
      return true;
  }
  return false;
}

Atom Molecule::addAtom(unsigned char atomicNumber)
{
  // Mark the graph as dirty.
  m_graphDirty = true;

  // Add the atomic number.
  m_atomicNumbers.push_back(atomicNumber);

  return Atom(this, m_atomicNumbers.size() - 1);
}

bool Molecule::removeAtom(size_t index)
{
  if (index >= atomCount())
    return false;

  // Before removing the atom we must first remove any bonds to it.
  std::vector<Bond> atomBonds = bonds(atom(index));
  while (atomBonds.size()) {
    removeBond(atomBonds.back());
    atomBonds = bonds(atom(index));
  }

  size_t newSize = m_atomicNumbers.size() - 1;
  if (index != newSize) {
    // We need to move the last atom to this position, and update its unique ID.
    m_atomicNumbers[index] = m_atomicNumbers.back();
    if (m_positions2d.size() == m_atomicNumbers.size())
      m_positions2d[index] = m_positions2d.back();
    if (m_positions3d.size() == m_atomicNumbers.size())
      m_positions3d[index] = m_positions3d.back();

    // Find any bonds to the moved atom and update their index.
    atomBonds = bonds(atom(newSize));
    for (std::vector<Bond>::const_iterator it = atomBonds.begin(),
         itEnd = atomBonds.end(); it != itEnd; ++it) {
      std::pair<size_t, size_t> bondPair = m_bondPairs[it->index()];
      if (bondPair.first == newSize)
        bondPair.first = index;
      else if (bondPair.second == newSize)
        bondPair.second = index;
      m_bondPairs[it->index()] = bondPair;
    }
  }
  // Resize the arrays for the smaller molecule.
  if (m_positions2d.size() == m_atomicNumbers.size())
    m_positions2d.pop_back();
  if (m_positions3d.size() == m_atomicNumbers.size())
    m_positions3d.pop_back();
  m_atomicNumbers.pop_back();

  return true;
}

bool Molecule::removeAtom(const Atom &atom_)
{
  return removeAtom(atom_.index());
}

void Molecule::clearAtoms()
{
  while (atomCount() != 0)
    removeAtom(static_cast<size_t>(0));
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

bool Molecule::removeBond(size_t index)
{
  if (index >= bondCount())
    return false;

  size_t newSize = m_bondOrders.size() - 1;
  if (index != newSize) {
    m_bondOrders[index] = m_bondOrders.back();
    m_bondPairs[index] = m_bondPairs.back();
  }
  m_bondOrders.pop_back();
  m_bondPairs.pop_back();
  return true;
}

bool Molecule::removeBond(const Bond &bond_)
{
  return removeBond(bond_.index());
}

bool Molecule::removeBond(const Atom &a, const Atom &b)
{
  return removeBond(bond(a, b).index());
}

void Molecule::clearBonds()
{
  while (bondCount())
    removeBond(static_cast<size_t>(0));
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

Mesh* Molecule::addMesh()
{
  m_meshes.push_back(new Mesh);
  return m_meshes.back();
}

Mesh* Molecule::mesh(size_t index)
{
  if (index < m_meshes.size())
    return m_meshes[index];
  else
    return NULL;
}

const Mesh* Molecule::mesh(size_t index) const
{
  if (index < m_meshes.size())
    return m_meshes[index];
  else
    return NULL;
}

void Molecule::clearMeshes()
{
  while(!m_meshes.empty()) {
    delete m_meshes.back();
    m_meshes.pop_back();
  }
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
    result << "C";
    if (iter->second > 1)
      result << iter->second;
    composition.erase(iter);

    // If carbon is present, hydrogens are next.
    iter = composition.find(1);
    if (iter != composition.end()) {
      result << "H";
      if (iter->second > 1)
        result << iter->second;
      composition.erase(iter);
    }
  }

  // The rest:
  iter = composition.begin();
  while (iter != composition.end()) {
    result << Elements::symbol(iter->first);
    if (iter->second > 1)
      result << iter->second;
    ++iter;
  }

  return result.str();
}

void Molecule::setUnitCell(UnitCell *uc)
{
  if (uc != m_unitCell) {
    delete m_unitCell;
    m_unitCell = uc;
  }
}

// bond perception code ported from VTK's vtkSimpleBondPerceiver class
void Molecule::perceiveBondsSimple()
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
