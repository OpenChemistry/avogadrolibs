/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011-2014 Kitware, Inc. and Geoffrey Hutchison

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
#include "cube.h"
#include "elements.h"
#include "mesh.h"
#include "residue.h"
#include "unitcell.h"

#include <algorithm>
#include <cassert>

namespace Avogadro {
namespace Core {

Molecule::Molecule()
  : m_graphDirty(false)
  , m_basisSet(nullptr)
  , m_unitCell(nullptr)
{}

Molecule::Molecule(const Molecule& other)
  : m_graph(other.m_graph)
  , m_graphDirty(true)
  , m_data(other.m_data)
  , m_customElementMap(other.m_customElementMap)
  , m_atomicNumbers(other.atomicNumbers())
  , m_positions2d(other.m_positions2d)
  , m_positions3d(other.m_positions3d)
  , m_coordinates3d(other.m_coordinates3d)
  , m_timesteps(other.m_timesteps)
  , m_hybridizations(other.m_hybridizations)
  , m_formalCharges(other.m_formalCharges)
  , m_vibrationFrequencies(other.m_vibrationFrequencies)
  , m_vibrationIntensities(other.m_vibrationIntensities)
  , m_vibrationLx(other.m_vibrationLx)
  , m_bondPairs(other.m_bondPairs)
  , m_bondOrders(other.m_bondOrders)
  , m_selectedAtoms(other.m_selectedAtoms)
  , m_meshes(std::vector<Mesh*>())
  , m_cubes(std::vector<Cube*>())
  , m_basisSet(other.m_basisSet ? other.m_basisSet->clone() : nullptr)
  , m_unitCell(other.m_unitCell ? new UnitCell(*other.m_unitCell) : nullptr)
  , m_residues(other.m_residues)
{
  // Copy over any meshes
  for (Index i = 0; i < other.meshCount(); ++i) {
    Mesh* m = addMesh();
    *m = *other.mesh(i);
  }

  // Copy over any cubes
  for (Index i = 0; i < other.cubeCount(); ++i) {
    Cube* c = addCube();
    *c = *other.cube(i);
  }
}

Molecule::Molecule(Molecule&& other) noexcept
  : m_graph(std::move(other.m_graph))
  , m_graphDirty(std::move(other.m_graphDirty))
  , m_data(std::move(other.m_data))
  , m_customElementMap(std::move(other.m_customElementMap))
  , m_atomicNumbers(std::move(other.atomicNumbers()))
  , m_positions2d(std::move(other.m_positions2d))
  , m_positions3d(std::move(other.m_positions3d))
  , m_coordinates3d(std::move(other.m_coordinates3d))
  , m_timesteps(std::move(other.m_timesteps))
  , m_hybridizations(std::move(other.m_hybridizations))
  , m_formalCharges(std::move(other.m_formalCharges))
  , m_vibrationFrequencies(std::move(other.m_vibrationFrequencies))
  , m_vibrationIntensities(std::move(other.m_vibrationIntensities))
  , m_vibrationLx(std::move(other.m_vibrationLx))
  , m_bondPairs(std::move(other.m_bondPairs))
  , m_bondOrders(std::move(other.m_bondOrders))
  , m_selectedAtoms(std::move(other.m_selectedAtoms))
  , m_meshes(std::move(other.m_meshes))
  , m_cubes(std::move(other.m_cubes))
  , m_residues(std::move(other.m_residues))
{
  m_basisSet = other.m_basisSet;
  other.m_basisSet = nullptr;

  m_unitCell = other.m_unitCell;
  other.m_unitCell = nullptr;
}

Molecule& Molecule::operator=(const Molecule& other)
{
  if (this != &other) {
    m_graph = other.m_graph;
    m_graphDirty = true;
    m_data = other.m_data;
    m_customElementMap = other.m_customElementMap;
    m_atomicNumbers = other.m_atomicNumbers;
    m_positions2d = other.m_positions2d;
    m_positions3d = other.m_positions3d;
    m_coordinates3d = other.m_coordinates3d;
    m_timesteps = other.m_timesteps;
    m_hybridizations = other.m_hybridizations;
    m_formalCharges = other.m_formalCharges;
    m_vibrationFrequencies = other.m_vibrationFrequencies;
    m_vibrationIntensities = other.m_vibrationIntensities;
    m_vibrationLx = other.m_vibrationLx;
    m_bondPairs = other.m_bondPairs;
    m_bondOrders = other.m_bondOrders;
    m_selectedAtoms = other.m_selectedAtoms;
    m_residues = other.m_residues;

    clearMeshes();

    // Copy over any meshes
    for (Index i = 0; i < other.meshCount(); ++i) {
      Mesh* m = addMesh();
      *m = *other.mesh(i);
    }

    clearCubes();

    // Copy over any cubes
    for (Index i = 0; i < other.cubeCount(); ++i) {
      Cube* c = addCube();
      *c = *other.cube(i);
    }

    delete m_basisSet;
    m_basisSet = other.m_basisSet ? other.m_basisSet->clone() : nullptr;
    delete m_unitCell;
    m_unitCell = other.m_unitCell ? new UnitCell(*other.m_unitCell) : nullptr;
  }

  return *this;
}

Molecule& Molecule::operator=(Molecule&& other) noexcept
{
  if (this != &other) {
    m_graph = std::move(other.m_graph);
    m_graphDirty = std::move(other.m_graphDirty);
    m_data = std::move(other.m_data);
    m_customElementMap = std::move(other.m_customElementMap);
    m_atomicNumbers = std::move(other.m_atomicNumbers);
    m_positions2d = std::move(other.m_positions2d);
    m_positions3d = std::move(other.m_positions3d);
    m_coordinates3d = std::move(other.m_coordinates3d);
    m_timesteps = std::move(other.m_timesteps);
    m_hybridizations = std::move(other.m_hybridizations);
    m_formalCharges = std::move(other.m_formalCharges);
    m_vibrationFrequencies = std::move(other.m_vibrationFrequencies);
    m_vibrationIntensities = std::move(other.m_vibrationIntensities);
    m_vibrationLx = std::move(other.m_vibrationLx);
    m_bondPairs = std::move(other.m_bondPairs);
    m_bondOrders = std::move(other.m_bondOrders);
    m_selectedAtoms = std::move(other.m_selectedAtoms);
    m_residues = std::move(other.m_residues);

    clearMeshes();
    m_meshes = std::move(other.m_meshes);

    clearCubes();
    m_cubes = std::move(other.m_cubes);

    delete m_basisSet;
    m_basisSet = other.m_basisSet;
    other.m_basisSet = nullptr;

    delete m_unitCell;
    m_unitCell = other.m_unitCell;
    other.m_unitCell = nullptr;
  }

  return *this;
}

Molecule::~Molecule()
{
  delete m_basisSet;
  delete m_unitCell;
  clearMeshes();
  clearCubes();
}

void Molecule::setData(const std::string& name, const Variant& value)
{
  m_data.setValue(name, value);
}

Variant Molecule::data(const std::string& name) const
{
  return m_data.value(name);
}

bool Molecule::hasData(const std::string& name) const
{
  return m_data.hasValue(name);
}

void Molecule::setDataMap(const VariantMap& map)
{
  m_data = map;
}

const VariantMap& Molecule::dataMap() const
{
  return m_data;
}

VariantMap& Molecule::dataMap()
{
  return m_data;
}

Array<unsigned char>& Molecule::atomicNumbers()
{
  return m_atomicNumbers;
}

const Array<unsigned char>& Molecule::atomicNumbers() const
{
  return m_atomicNumbers;
}

Array<AtomHybridization>& Molecule::hybridizations()
{
  return m_hybridizations;
}

const Array<AtomHybridization>& Molecule::hybridizations() const
{
  return m_hybridizations;
}

Array<signed char>& Molecule::formalCharges()
{
  return m_formalCharges;
}

const Array<signed char>& Molecule::formalCharges() const
{
  return m_formalCharges;
}

Array<Vector2>& Molecule::atomPositions2d()
{
  return m_positions2d;
}

const Array<Vector2>& Molecule::atomPositions2d() const
{
  return m_positions2d;
}

Array<Vector3>& Molecule::atomPositions3d()
{
  return m_positions3d;
}

const Array<Vector3>& Molecule::atomPositions3d() const
{
  return m_positions3d;
}

Array<std::pair<Index, Index>>& Molecule::bondPairs()
{
  return m_bondPairs;
}

const Array<std::pair<Index, Index>>& Molecule::bondPairs() const
{
  return m_bondPairs;
}

Array<unsigned char>& Molecule::bondOrders()
{
  return m_bondOrders;
}

const Array<unsigned char>& Molecule::bondOrders() const
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

const Molecule::CustomElementMap& Molecule::customElementMap() const
{
  return m_customElementMap;
}

void Molecule::setCustomElementMap(const Molecule::CustomElementMap& map)
{
  m_customElementMap = map;
}

bool Molecule::hasCustomElements() const
{
  for (Array<unsigned char>::const_iterator it = m_atomicNumbers.begin(),
                                            itEnd = m_atomicNumbers.end();
       it != itEnd; ++it) {
    if (Core::isCustomElement(*it))
      return true;
  }
  return false;
}

Molecule::AtomType Molecule::addAtom(unsigned char number)
{
  // Mark the graph as dirty.
  m_graphDirty = true;

  // Add the atomic number.
  m_atomicNumbers.push_back(number);

  return AtomType(this, static_cast<Index>(m_atomicNumbers.size() - 1));
}

bool Molecule::removeAtom(Index index)
{
  if (index >= atomCount())
    return false;

  // Before removing the atom we must first remove any bonds to it.
  Array<BondType> atomBonds = bonds(atom(index));
  while (atomBonds.size()) {
    removeBond(atomBonds.back());
    atomBonds = bonds(atom(index));
  }

  Index newSize = static_cast<Index>(m_atomicNumbers.size() - 1);
  if (index != newSize) {
    // We need to move the last atom to this position, and update its unique ID.
    m_atomicNumbers[index] = m_atomicNumbers.back();
    if (m_positions2d.size() == m_atomicNumbers.size())
      m_positions2d[index] = m_positions2d.back();
    if (m_positions3d.size() == m_atomicNumbers.size())
      m_positions3d[index] = m_positions3d.back();
    if (m_hybridizations.size() == m_atomicNumbers.size())
      m_hybridizations[index] = m_hybridizations.back();
    if (m_formalCharges.size() == m_atomicNumbers.size())
      m_formalCharges[index] = m_formalCharges.back();

    // Find any bonds to the moved atom and update their index.
    atomBonds = bonds(atom(newSize));
    for (Array<BondType>::const_iterator it = atomBonds.begin(),
                                         itEnd = atomBonds.end();
         it != itEnd; ++it) {
      std::pair<Index, Index> pair = m_bondPairs[it->index()];
      if (pair.first == newSize)
        pair.first = index;
      else if (pair.second == newSize)
        pair.second = index;
      m_bondPairs[it->index()] = pair;
    }
  }
  // Resize the arrays for the smaller molecule.
  if (m_positions2d.size() == m_atomicNumbers.size())
    m_positions2d.pop_back();
  if (m_positions3d.size() == m_atomicNumbers.size())
    m_positions3d.pop_back();
  if (m_hybridizations.size() == m_atomicNumbers.size())
    m_hybridizations.pop_back();
  if (m_formalCharges.size() == m_atomicNumbers.size())
    m_formalCharges.pop_back();
  m_atomicNumbers.pop_back();

  return true;
}

bool Molecule::removeAtom(const AtomType& atom_)
{
  return removeAtom(atom_.index());
}

void Molecule::clearAtoms()
{
  while (atomCount() != 0)
    removeAtom(0);
}

Molecule::AtomType Molecule::atom(Index index) const
{
  assert(index < atomCount());
  return AtomType(const_cast<Molecule*>(this), index);
}

Index Molecule::atomCount() const
{
  return static_cast<Index>(m_atomicNumbers.size());
}

Index Molecule::atomCount(unsigned char number) const
{
  Index count(0);
  for (Array<unsigned char>::const_iterator it = m_atomicNumbers.begin();
       it != m_atomicNumbers.end(); ++it) {
    if (*it == number)
      ++count;
  }
  return count;
}

namespace {
// Make an std::pair where the lower index is always first in the pair. This
// offers us the guarantee that any given pair of atoms will always result in
// a pair that is the same no matter what the order of the atoms given.
std::pair<Index, Index> makeBondPair(const Index& a, const Index& b)
{
  return a < b ? std::make_pair(a, b) : std::make_pair(b, a);
}
}

Molecule::BondType Molecule::addBond(Index atom1, Index atom2,
                                     unsigned char order)
{
  assert(atom1 < atomCount());
  assert(atom2 < atomCount());

  m_graphDirty = true;
  m_bondPairs.push_back(makeBondPair(atom1, atom2));
  m_bondOrders.push_back(order);

  return BondType(this, bondCount() - 1);
}

Molecule::BondType Molecule::addBond(const AtomType& a, const AtomType& b,
                                     unsigned char order)
{
  assert(a.isValid() && a.molecule() == this);
  assert(b.isValid() && b.molecule() == this);

  m_graphDirty = true;
  m_bondPairs.push_back(makeBondPair(a.index(), b.index()));
  m_bondOrders.push_back(order);

  return BondType(this, static_cast<Index>(m_bondPairs.size() - 1));
}

bool Molecule::removeBond(Index index)
{
  if (index >= bondCount())
    return false;

  Index newSize = static_cast<Index>(m_bondOrders.size() - 1);
  if (index != newSize) {
    m_bondOrders[index] = m_bondOrders.back();
    m_bondPairs[index] = m_bondPairs.back();
  }
  m_bondOrders.pop_back();
  m_bondPairs.pop_back();
  return true;
}

bool Molecule::removeBond(const BondType& bond_)
{
  return removeBond(bond_.index());
}

bool Molecule::removeBond(Index a, Index b)
{
  return removeBond(bond(a, b).index());
}

bool Molecule::removeBond(const AtomType& a, const AtomType& b)
{
  return removeBond(bond(a, b).index());
}

void Molecule::clearBonds()
{
  while (bondCount())
    removeBond(0);
}

Molecule::BondType Molecule::bond(Index index) const
{
  assert(index < bondCount());

  return BondType(const_cast<Molecule*>(this), index);
}

Molecule::BondType Molecule::bond(const AtomType& a, const AtomType& b) const
{
  assert(a.isValid() && a.molecule() == this);
  assert(b.isValid() && b.molecule() == this);

  std::pair<Index, Index> pair = makeBondPair(a.index(), b.index());

  Array<std::pair<Index, Index>>::const_iterator iter =
    std::find(m_bondPairs.begin(), m_bondPairs.end(), pair);

  if (iter == m_bondPairs.end())
    return BondType();

  Index index = static_cast<Index>(std::distance(m_bondPairs.begin(), iter));

  return BondType(const_cast<Molecule*>(this), index);
}

Molecule::BondType Molecule::bond(Index atomId1, Index atomId2) const
{
  assert(atomId1 < atomCount());
  assert(atomId2 < atomCount());

  std::pair<Index, Index> pair = makeBondPair(atomId1, atomId2);

  Array<std::pair<Index, Index>>::const_iterator iter =
    std::find(m_bondPairs.begin(), m_bondPairs.end(), pair);

  if (iter == m_bondPairs.end())
    return BondType();

  Index index = static_cast<Index>(std::distance(m_bondPairs.begin(), iter));

  return BondType(const_cast<Molecule*>(this), index);
}

Array<Molecule::BondType> Molecule::bonds(const AtomType& a)
{
  if (!a.isValid())
    return Array<BondType>();
  Array<BondType> atomBonds;
  Index atomIndex = a.index();
  for (Index i = 0; i < m_bondPairs.size(); ++i)
    if (m_bondPairs[i].first == atomIndex || m_bondPairs[i].second == atomIndex)
      atomBonds.push_back(BondType(this, i));
  return atomBonds;
}

Array<Molecule::BondType> Molecule::bonds(Index a)
{
  Array<BondType> atomBonds;
  if (a < atomCount()) {
    for (Index i = 0; i < m_bondPairs.size(); ++i)
      if (m_bondPairs[i].first == a || m_bondPairs[i].second == a)
        atomBonds.push_back(BondType(this, i));
  }
  return atomBonds;
}

Index Molecule::bondCount() const
{
  return m_bondPairs.size();
}

Mesh* Molecule::addMesh()
{
  m_meshes.push_back(new Mesh);
  return m_meshes.back();
}

Mesh* Molecule::mesh(Index index)
{
  if (index < static_cast<Index>(m_meshes.size()))
    return m_meshes[index];
  else
    return nullptr;
}

const Mesh* Molecule::mesh(Index index) const
{
  if (index < static_cast<Index>(m_meshes.size()))
    return m_meshes[index];
  else
    return nullptr;
}

void Molecule::clearMeshes()
{
  while (!m_meshes.empty()) {
    delete m_meshes.back();
    m_meshes.pop_back();
  }
}

Cube* Molecule::addCube()
{
  m_cubes.push_back(new Cube);
  return m_cubes.back();
}

Cube* Molecule::cube(Index index)
{
  if (index < static_cast<Index>(m_cubes.size()))
    return m_cubes[index];
  else
    return nullptr;
}

const Cube* Molecule::cube(Index index) const
{
  if (index < static_cast<Index>(m_cubes.size()))
    return m_cubes[index];
  else
    return nullptr;
}

void Molecule::clearCubes()
{
  while (!m_cubes.empty()) {
    delete m_cubes.back();
    m_cubes.pop_back();
  }
}

std::string Molecule::formula(const std::string& delimiter, int over) const
{
  // Adapted from chemkit:
  // A map of atomic symbols to their quantity.
  std::map<unsigned char, size_t> composition;
  for (Array<unsigned char>::const_iterator it = m_atomicNumbers.begin(),
                                            itEnd = m_atomicNumbers.end();
       it != itEnd; ++it) {
    composition[*it]++;
  }

  std::stringstream result;
  std::map<unsigned char, size_t>::iterator iter;

  // Carbons first
  iter = composition.find(6);
  if (iter != composition.end()) {
    result << "C";
    if (iter->second > static_cast<size_t>(over))
      result << delimiter << iter->second;
    composition.erase(iter);

    // If carbon is present, hydrogens are next.
    iter = composition.find(1);
    if (iter != composition.end()) {
      result << delimiter << "H";
      if (iter->second > static_cast<size_t>(over))
        result << delimiter << iter->second;
      composition.erase(iter);
    }
  }

  // The rest:
  iter = composition.begin();
  while (iter != composition.end()) {
    result << delimiter << Elements::symbol(iter->first);
    if (iter->second > static_cast<size_t>(over))
      result << delimiter << iter->second;
    ++iter;
  }

  return result.str();
}

void Molecule::setUnitCell(UnitCell* uc)
{
  if (uc != m_unitCell) {
    delete m_unitCell;
    m_unitCell = uc;
  }
}

double Molecule::mass() const
{
  double m(0.0);
  for (Index i = 0; i < atomCount(); ++i)
    m += Elements::mass(atom(i).atomicNumber());
  return m;
}

Array<double> Molecule::vibrationFrequencies() const
{
  return m_vibrationFrequencies;
}

void Molecule::setVibrationFrequencies(const Array<double>& freq)
{
  m_vibrationFrequencies = freq;
}

Array<double> Molecule::vibrationIntensities() const
{
  return m_vibrationIntensities;
}

void Molecule::setVibrationIntensities(const Array<double>& intensities)
{
  m_vibrationIntensities = intensities;
}

Array<Vector3> Molecule::vibrationLx(int mode) const
{
  if (mode >= 0 && mode < static_cast<int>(m_vibrationLx.size()))
    return m_vibrationLx[mode];
  return Array<Vector3>();
}

void Molecule::setVibrationLx(const Array<Array<Vector3>>& lx)
{
  m_vibrationLx = lx;
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
  for (size_t i = 0; i < radii.size(); i++) {
    radii[i] = Elements::radiusCovalent(m_atomicNumbers[i]);
    if (radii[i] <= 0.0)
      radii[i] = 2.0;
  }

  // check for bonds
  for (Index i = 0; i < atomCount(); i++) {
    Vector3 ipos = m_positions3d[i];
    for (Index j = i + 1; j < atomCount(); j++) {
      double cutoff = radii[i] + radii[j] + tolerance;
      Vector3 jpos = m_positions3d[j];
      Vector3 diff = jpos - ipos;

      if (std::fabs(diff[0]) > cutoff || std::fabs(diff[1]) > cutoff ||
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

void Molecule::perceiveBondsFromResidueData()
{
  for (Index i = 0; i < m_residues.size(); ++i) {
    m_residues[i].resolveResidueBonds(*this);
  }
}

int Molecule::coordinate3dCount()
{
  return static_cast<int>(m_coordinates3d.size());
}

bool Molecule::setCoordinate3d(int coord)
{
  if (coord >= 0 && coord < static_cast<int>(m_coordinates3d.size())) {
    m_positions3d = m_coordinates3d[coord];
    return true;
  }
  return false;
}

Array<Vector3> Molecule::coordinate3d(int index) const
{
  return m_coordinates3d[index];
}

bool Molecule::setCoordinate3d(const Array<Vector3>& coords, int index)
{
  if (static_cast<int>(m_coordinates3d.size()) <= index)
    m_coordinates3d.resize(index + 1);
  m_coordinates3d[index] = coords;
  return true;
}

double Molecule::timeStep(int index, bool& status)
{
  if (static_cast<int>(m_timesteps.size()) <= index) {
    status = false;
    return 0.0;
  }
  status = true;
  return m_timesteps[index];
}

bool Molecule::setTimeStep(double timestep, int index)
{
  if (static_cast<int>(m_timesteps.size()) <= index)
    m_timesteps.resize(index + 1);
  m_timesteps[index] = timestep;
  return true;
}

void Molecule::updateGraph() const
{
  if (!m_graphDirty)
    return;
  m_graphDirty = false;
  m_graph.clear();
  m_graph.setSize(atomCount());
  typedef Array<std::pair<Index, Index>>::const_iterator IterType;
  for (IterType it = m_bondPairs.begin(); it != m_bondPairs.end(); ++it) {
    m_graph.addEdge(it->first, it->second);
  }
}

Residue& Molecule::addResidue(std::string& name, Index& number, char& id)
{
  Residue newResidue(name, number, id);
  m_residues.push_back(newResidue);
  return m_residues[m_residues.size() - 1];
}

void Molecule::addResidue(Residue& residue)
{
  m_residues.push_back(residue);
}

Residue Molecule::residue(int index)
{
  return m_residues[index];
}

} // end Core namespace
} // end Avogadro namespace
