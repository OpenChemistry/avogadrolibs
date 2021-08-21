/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molecule.h"

#include "basisset.h"
#include "color3f.h"
#include "cube.h"
#include "elements.h"
#include "layermanager.h"
#include "mesh.h"
#include "residue.h"
#include "unitcell.h"

#include <algorithm>
#include <cassert>
#include <iostream>

namespace Avogadro {
namespace Core {

using std::swap;

Molecule::Molecule()
  : m_basisSet(nullptr), m_unitCell(nullptr), m_graphDirty(false),
    m_layers(LayerManager::getMoleculeLayer(this))
{}

Molecule::Molecule(const Molecule& other)
  : m_data(other.m_data), m_customElementMap(other.m_customElementMap),
    m_positions2d(other.m_positions2d), m_positions3d(other.m_positions3d),
    m_label(other.m_label), m_coordinates3d(other.m_coordinates3d),
    m_timesteps(other.m_timesteps), m_hybridizations(other.m_hybridizations),
    m_formalCharges(other.m_formalCharges), m_colors(other.m_colors),
    m_vibrationFrequencies(other.m_vibrationFrequencies),
    m_vibrationIntensities(other.m_vibrationIntensities),
    m_vibrationLx(other.m_vibrationLx), m_selectedAtoms(other.m_selectedAtoms),
    m_meshes(std::vector<Mesh*>()), m_cubes(std::vector<Cube*>()),
    m_basisSet(other.m_basisSet ? other.m_basisSet->clone() : nullptr),
    m_unitCell(other.m_unitCell ? new UnitCell(*other.m_unitCell) : nullptr),
    m_residues(other.m_residues), m_graph(other.m_graph),
    m_graphDirty(other.m_graphDirty), m_bondPairs(other.m_bondPairs),
    m_bondOrders(other.m_bondOrders), m_atomicNumbers(other.m_atomicNumbers),
    m_layers(LayerManager::getMoleculeLayer(&other, this))
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
  : m_data(std::move(other.m_data)),
    m_customElementMap(std::move(other.m_customElementMap)),
    m_positions2d(std::move(other.m_positions2d)),
    m_positions3d(std::move(other.m_positions3d)),
    m_label(std::move(other.m_label)),
    m_coordinates3d(std::move(other.m_coordinates3d)),
    m_timesteps(std::move(other.m_timesteps)),
    m_hybridizations(std::move(other.m_hybridizations)),
    m_formalCharges(std::move(other.m_formalCharges)),
    m_colors(std::move(other.m_colors)),
    m_vibrationFrequencies(std::move(other.m_vibrationFrequencies)),
    m_vibrationIntensities(std::move(other.m_vibrationIntensities)),
    m_vibrationLx(std::move(other.m_vibrationLx)),
    m_selectedAtoms(std::move(other.m_selectedAtoms)),
    m_meshes(std::move(other.m_meshes)), m_cubes(std::move(other.m_cubes)),
    m_residues(std::move(other.m_residues)), m_graph(std::move(other.m_graph)),
    m_graphDirty(std::move(other.m_graphDirty)),
    m_bondPairs(std::move(other.m_bondPairs)),
    m_bondOrders(std::move(other.m_bondOrders)),
    m_atomicNumbers(std::move(other.m_atomicNumbers)),
    m_layers(LayerManager::getMoleculeLayer(&other, this))
{
  m_basisSet = other.m_basisSet;
  other.m_basisSet = nullptr;

  m_unitCell = other.m_unitCell;
  other.m_unitCell = nullptr;
}

Molecule& Molecule::operator=(const Molecule& other)
{
  if (this != &other) {
    m_data = other.m_data;
    m_customElementMap = other.m_customElementMap;
    m_positions2d = other.m_positions2d;
    m_positions3d = other.m_positions3d;
    m_label = other.m_label;
    m_coordinates3d = other.m_coordinates3d;
    m_timesteps = other.m_timesteps;
    m_hybridizations = other.m_hybridizations;
    m_formalCharges = other.m_formalCharges;
    m_colors = other.m_colors,
    m_vibrationFrequencies = other.m_vibrationFrequencies;
    m_vibrationIntensities = other.m_vibrationIntensities;
    m_vibrationLx = other.m_vibrationLx;
    m_selectedAtoms = other.m_selectedAtoms;
    m_residues = other.m_residues;
    m_graph = other.m_graph;
    m_graphDirty = other.m_graphDirty;
    m_bondPairs = other.m_bondPairs;
    m_bondOrders = other.m_bondOrders;
    m_atomicNumbers = other.m_atomicNumbers;

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

  m_layers = LayerManager::getMoleculeLayer(&other, this);

  return *this;
}

Molecule& Molecule::operator=(Molecule&& other) noexcept
{
  if (this != &other) {
    m_data = std::move(other.m_data);
    m_customElementMap = std::move(other.m_customElementMap);
    m_positions2d = std::move(other.m_positions2d);
    m_positions3d = std::move(other.m_positions3d);
    m_label = std::move(other.m_label);
    m_coordinates3d = std::move(other.m_coordinates3d);
    m_timesteps = std::move(other.m_timesteps);
    m_hybridizations = std::move(other.m_hybridizations);
    m_formalCharges = std::move(other.m_formalCharges);
    m_colors = std::move(other.m_colors);
    m_vibrationFrequencies = std::move(other.m_vibrationFrequencies);
    m_vibrationIntensities = std::move(other.m_vibrationIntensities);
    m_vibrationLx = std::move(other.m_vibrationLx);
    m_selectedAtoms = std::move(other.m_selectedAtoms);
    m_residues = std::move(other.m_residues);
    m_graph = std::move(other.m_graph);
    m_graphDirty = std::move(other.m_graphDirty);
    m_bondPairs = std::move(other.m_bondPairs);
    m_bondOrders = std::move(other.m_bondOrders);
    m_atomicNumbers = std::move(other.m_atomicNumbers);

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

  m_layers = LayerManager::getMoleculeLayer(&other, this);

  return *this;
}

Molecule::~Molecule()
{
  LayerManager::deleteMolecule(this);
  delete m_basisSet;
  delete m_unitCell;
  clearMeshes();
  clearCubes();
}

Layer& Molecule::layer()
{
  return m_layers;
}
const Layer& Molecule::layer() const
{
  return m_layers;
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

Array<Vector3ub>& Molecule::colors()
{
  return m_colors;
}

const Array<Vector3ub>& Molecule::colors() const
{
  return m_colors;
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

const Molecule::CustomElementMap& Molecule::customElementMap() const
{
  return m_customElementMap;
}

void Molecule::setCustomElementMap(const Molecule::CustomElementMap& map)
{
  m_customElementMap = map;
}

Molecule::AtomType Molecule::addAtom(unsigned char number)
{
  if (!m_graphDirty) {
    m_graph.addVertex();
  }
  m_atomicNumbers.push_back(number);
  m_layers.addAtomToActiveLayer(atomCount() - 1);
  return AtomType(this, static_cast<Index>(atomCount() - 1));
}

Molecule::AtomType Molecule::addAtom(unsigned char number, Vector3 position3d)
{
  if (m_positions3d.size() == atomCount()) {
    m_positions3d.push_back(position3d);
  }
  return Molecule::addAtom(number);
}

void Molecule::swapBond(Index a, Index b)
{
  swap(m_bondPairs[a], m_bondPairs[b]);
  swap(m_bondOrders[a], m_bondOrders[b]);
}
void Molecule::swapAtom(Index a, Index b)
{
  Index max = a > b ? a : b;
  if (m_positions2d.size() >= max)
    swap(m_positions2d[a], m_positions2d[b]);
  if (m_positions3d.size() >= max)
    swap(m_positions3d[a], m_positions3d[b]);
  if (m_hybridizations.size() >= max)
    swap(m_hybridizations[a], m_hybridizations[b]);
  if (m_formalCharges.size() >= max)
    swap(m_formalCharges[a], m_formalCharges[b]);
  if (m_colors.size() >= max)
    swap(m_colors[a], m_colors[b]);

  swap(m_atomicNumbers[a], m_atomicNumbers[b]);
  for (auto& pair : m_bondPairs) {
    auto oldPair = pair;
    bool changed = false;
    if (pair.first == a) {
      pair.first = b;
      changed = true;
    } else if (pair.first == b) {
      pair.first = a;
      changed = true;
    }
    if (pair.second == a) {
      pair.second = b;
      changed = true;
    } else if (pair.second == b) {
      pair.second = a;
      changed = true;
    }

    if (changed && !m_graphDirty) {
      m_graph.removeEdge(oldPair.first, oldPair.second);
      m_graph.addEdge(pair.first, pair.second);
    }
  }
  m_layers.swapLayer(a, b);
}

bool Molecule::removeAtom(Index index)
{
  if (index >= atomCount())
    return false;
  if (m_positions2d.size() == atomCount())
    m_positions2d.swapAndPop(index);
  if (m_positions3d.size() == atomCount())
    m_positions3d.swapAndPop(index);
  if (m_hybridizations.size() == atomCount())
    m_hybridizations.swapAndPop(index);
  if (m_formalCharges.size() == atomCount())
    m_formalCharges.swapAndPop(index);
  if (m_colors.size() == atomCount())
    m_colors.swapAndPop(index);

  if (m_selectedAtoms.size() == atomCount()) {
    // swap and pop on std::vector<bool>
    if (index != m_selectedAtoms.size() - 1) {
      m_selectedAtoms[index] = m_selectedAtoms.back();
    }
    m_selectedAtoms.pop_back();
  }

  Index affectedIndex = static_cast<Index>(m_atomicNumbers.size() - 1);
  m_atomicNumbers.swapAndPop(index);
  removeBonds(index);
  if (!m_graphDirty) {
    m_graph.removeVertex(index);
  }
  // the bonds from back() now are in index, so we need to rebond it
  rebondBond(index, affectedIndex);
  m_layers.removeAtom(index);
  return true;
  return true;
}

bool Molecule::removeAtom(const AtomType& atom_)
{
  return removeAtom(atom_.index());
}

void Molecule::clearAtoms()
{
  m_positions2d.clear();
  m_positions3d.clear();
  m_label.clear();
  m_hybridizations.clear();
  m_formalCharges.clear();
  m_colors.clear();
  m_atomicNumbers.clear();
  m_bondOrders.clear();
  m_bondPairs.clear();
  m_graph.clear();
  m_graphDirty = false;
}

Molecule::AtomType Molecule::atom(Index index) const
{
  assert(index < atomCount());
  return AtomType(const_cast<Molecule*>(this), index);
}

Molecule::BondType Molecule::addBond(Index atom1, Index atom2,
                                     unsigned char order)
{
  assert(atom1 < m_atomicNumbers.size());
  assert(atom2 < m_atomicNumbers.size());
  Index index = bond(atom1, atom2).index();
  if (index >= bondCount()) {
    if (!m_graphDirty) {
      m_graph.addEdge(atom1, atom2);
    }
    m_bondPairs.push_back(Molecule::makeBondPair(atom1, atom2));
    m_bondOrders.push_back(order);
    index = static_cast<Index>(m_bondPairs.size() - 1);
  } else {
    m_bondOrders[index] = order;
  }
  return BondType(this, index);
}

Molecule::BondType Molecule::addBond(const AtomType& a, const AtomType& b,
                                     unsigned char order)
{
  assert(a.isValid() && a.molecule() == this);
  assert(b.isValid() && b.molecule() == this);

  return addBond(a.index(), b.index(), order);
}

size_t calcNlogN(size_t n)
{
  size_t aproxLog = 1;
  float aux = n;
  while (aux > 2.0f) {
    aux /= 2.0f;
    ++aproxLog;
  }
  return n * aproxLog;
}

bool Molecule::removeBond(Index index)
{
  if (index >= bondCount())
    return false;
  if (!m_graphDirty) {
    // mark dirty the graph O(n) only if is more efficient than remove an edge
    // O(nlogn)
    size_t n = atomCount();
    size_t m = calcNlogN(m_graph.subgraphCount(m_bondPairs[index].first));
    if (m < n) {
      m_graph.removeEdge(m_bondPairs[index].first, m_bondPairs[index].second);
    } else {
      m_graphDirty = true;
    }
  }
  m_bondOrders.swapAndPop(index);
  m_bondPairs.swapAndPop(index);
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
  m_bondOrders.clear();
  m_bondPairs.clear();
  m_graph.removeEdges();
  m_graph.setSize(atomCount());
  m_graphDirty = false;
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

  return bond(a.index(), b.index());
}

Molecule::BondType Molecule::bond(Index atomId1, Index atomId2) const
{
  assert(atomId1 < atomCount());
  assert(atomId2 < atomCount());

  std::pair<Index, Index> pair = Molecule::makeBondPair(atomId1, atomId2);
  Array<std::pair<Index, Index>>::const_iterator iter =
    std::find(m_bondPairs.begin(), m_bondPairs.end(), pair);

  Index index = static_cast<Index>(std::distance(m_bondPairs.begin(), iter));

  if (index >= bondCount())
    return BondType();
  return BondType(const_cast<Molecule*>(this), index);
}

Array<Molecule::BondType> Molecule::bonds(const AtomType& a)
{
  if (!a.isValid())
    return Array<BondType>();

  return bonds(a.index());
}

Array<const Molecule::BondType*> Molecule::bonds(Index a) const
{
  Array<const BondType*> atomBonds;
  if (a < atomCount()) {
    for (Index i = 0; i < m_bondPairs.size(); ++i)
      if (m_bondPairs[i].first == a || m_bondPairs[i].second == a) {
        // work arround to consult bonds without breaking constantness
        atomBonds.push_back(new BondType(const_cast<Molecule*>(this), i));
      }
  }
  return atomBonds;
}

Array<Molecule::BondType> Molecule::bonds(Index a)
{
  Array<BondType> atomBonds;
  if (a < atomCount()) {
    for (Index i = 0; i < bondCount(); ++i) {
      auto bond = bondPair(i);
      if (bond.first == a || bond.second == a)
        atomBonds.push_back(BondType(this, i));
    }
  }
  return atomBonds;
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
  std::map<unsigned char, size_t> componentsCount = composition();

  std::stringstream result;
  std::map<unsigned char, size_t>::iterator iter;

  // Carbons first
  iter = componentsCount.find(6);
  if (iter != componentsCount.end()) {
    result << "C";
    if (iter->second > static_cast<size_t>(over))
      result << delimiter << iter->second;
    componentsCount.erase(iter);

    // If carbon is present, hydrogens are next.
    iter = componentsCount.find(1);
    if (iter != componentsCount.end()) {
      result << delimiter << "H";
      if (iter->second > static_cast<size_t>(over))
        result << delimiter << iter->second;
      componentsCount.erase(iter);
    }
  }

  // The rest:
  iter = componentsCount.begin();
  while (iter != componentsCount.end()) {
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

Vector3 Molecule::centerOfGeometry() const
{
  Vector3 center(0.0, 0.0, 0.0);
  for (Index i = 0; i < atomCount(); ++i)
    center += atom(i).position3d();
  return center / atomCount();
}

Vector3 Molecule::centerOfMass() const
{
  Vector3 center(0.0, 0.0, 0.0);
  for (Index i = 0; i < atomCount(); ++i) {
    AtomType curr_atom = atom(i);
    center +=
      (curr_atom.position3d() * Elements::mass(curr_atom.atomicNumber()));
  }
  center /= mass();
  center /= atomCount();
  return center;
}

double Molecule::radius() const
{
  double radius = 0.0;
  if (atomCount() > 0) {
    radius = (centerOfGeometry() - atom(0).position3d()).norm();
  }
  return radius;
}

std::pair<Vector3, Vector3> Molecule::bestFitPlane() const
{
  return bestFitPlane(atomPositions3d());
}

std::pair<Vector3, Vector3> Molecule::bestFitPlane(const Array<Vector3>& pos)
{
  // copy coordinates to matrix in Eigen format
  size_t num_atoms = pos.size();
  assert(num_atoms >= 3);
  Eigen::Matrix<Vector3::Scalar, Eigen::Dynamic, Eigen::Dynamic> coord(
    3, num_atoms);
  for (size_t i = 0; i < num_atoms; ++i) {
    coord.col(i) = pos[i];
  }

  // calculate centroid
  Vector3 centroid = coord.rowwise().mean();

  // subtract centroid
  coord.colwise() -= centroid;

  // we only need the left-singular matrix
  auto svd = coord.jacobiSvd(Eigen::ComputeThinU | Eigen::ComputeThinV);
  Vector3 plane_normal = svd.matrixU().rightCols<1>();

  return std::make_pair(centroid, plane_normal);
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
void Molecule::perceiveBondsSimple(const double tolerance, const double min)
{
  // check for coordinates
  if (m_positions3d.size() != atomCount())
    return;

  // cache atomic radii
  std::vector<double> radii(atomCount());
  for (size_t i = 0; i < radii.size(); i++) {
    radii[i] = Elements::radiusCovalent(atomicNumber(i));
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
          (atomicNumber(i) == 1 && atomicNumber(j) == 1))
        continue;

      // check radius and add bond if needed
      double cutoffSq = cutoff * cutoff;
      double diffsq = diff.squaredNorm();
      if (diffsq < cutoffSq && diffsq > min * min)
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

Array<Vector3>& Molecule::forceVectors()
{
  return m_forceVectors;
}

const Array<Vector3>& Molecule::forceVectors() const
{
  return m_forceVectors;
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

Residue& Molecule::residue(Index index)
{
  return m_residues[index];
}

Index Molecule::residueCount() const
{
  return static_cast<Index>(m_residues.size());
}

bool Molecule::setBondPairs(const Array<std::pair<Index, Index>>& pairs)
{
  if (pairs.size() == bondCount()) {
    Index bond = 0;
    for (const auto& pair : pairs) {
      setBondPair(bond, pair);
      ++bond;
    }
    return true;
  }
  return false;
}

bool Molecule::setBondPair(Index bondId, const std::pair<Index, Index>& pair)
{
  if (bondId < bondCount()) {
    if (!m_graphDirty) {
      m_graph.removeEdge(m_bondPairs[bondId].first, m_bondPairs[bondId].second);
      m_graph.addEdge(pair.first, pair.second);
    }
    m_bondPairs[bondId] = pair;
    return true;
  }
  return false;
}

unsigned char Molecule::bondOrder(Index bondId) const
{
  return bondId < m_bondOrders.size() ? m_bondOrders[bondId] : 0;
}

bool Molecule::setBondOrders(const Array<unsigned char>& orders)
{
  if (orders.size() == bondCount()) {
    m_bondOrders = orders;
    return true;
  }
  return false;
}

bool Molecule::setBondOrder(Index bondId, unsigned char order)
{
  if (bondId < bondCount()) {
    m_bondOrders[bondId] = order;
    return true;
  }
  return false;
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

bool Molecule::setAtomicNumbers(const Core::Array<unsigned char>& nums)
{
  if (nums.size() == atomCount()) {
    m_atomicNumbers = nums;

    // update colors too
    if (nums.size() == m_colors.size()) {
      for (Index i = 0; i < nums.size(); ++i) {
        m_colors[i] = Vector3ub(Elements::color(atomicNumber(i)));
      }
    }

    return true;
  }
  return false;
}

bool Molecule::setAtomicNumber(Index atomId, unsigned char number)
{
  if (atomId < atomCount()) {
    m_atomicNumbers[atomId] = number;

    // update colors too
    if (atomId < m_colors.size())
      m_colors[atomId] = Vector3ub(Elements::color(number));

    return true;
  }
  return false;
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

std::map<unsigned char, size_t> Molecule::composition() const
{
  // A map of atomic symbols to their quantity.
  std::map<unsigned char, size_t> composition;
  for (Array<unsigned char>::const_iterator it = m_atomicNumbers.begin(),
                                            itEnd = m_atomicNumbers.end();
       it != itEnd; ++it) {
    ++composition[*it];
  }
  return composition;
}

bool Molecule::removeBonds(Index atom)
{
  if (atom >= bondCount())
    return false;
  Index i = 0;
  while (i < m_bondPairs.size()) {
    auto& bond = m_bondPairs[i];
    if (bond.first == atom || bond.second == atom) {
      removeBond(i);
    } else {
      ++i;
    }
  }
  return true;
}

Array<std::pair<Index, Index>> Molecule::getAtomBonds(Index index) const
{
  Array<std::pair<Index, Index>> result;
  for (auto& pair : m_bondPairs) {
    if (pair.first == index) {
      result.push_back(pair);
    } else if (pair.second == index) {
      result.push_back(pair);
    }
  }
  return result;
}

Array<unsigned char> Molecule::getAtomOrders(Index index) const
{
  Array<unsigned char> result;
  Index i = 0;
  for (auto& pair : m_bondPairs) {
    if (pair.first == index) {
      result.push_back(m_bondOrders[i]);
    } else if (pair.second == index) {
      result.push_back(m_bondOrders[i]);
    }
    ++i;
  }
  return result;
}

void Molecule::addBonds(const Array<std::pair<Index, Index>>& bonds,
                        const Array<unsigned char>& orders)
{
  Index i = 0;
  for (auto p : bonds) {
    addBond(p.first, p.second, orders[i]);
    ++i;
  }
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
    if (it->first < atomCount() && it->second < atomCount()) {
      m_graph.addEdge(it->first, it->second);
    }
  }
}

void Molecule::rebondBond(Index newIndex, Index oldIndex)
{
  // nothing to do
  if (newIndex == oldIndex)
    return;
  for (auto& pair : m_bondPairs) {
    if (pair.first == oldIndex) {
      pair.first = newIndex;
    } else if (pair.second == oldIndex) {
      pair.second = newIndex;
    }
  }
  m_graphDirty = true;
}

std::list<Index> Molecule::getAtomsAtLayer(size_t layer)
{
  std::list<Index> result;
  // get the index in decreasing order so deleting won't corrupt data
  for (Index i = atomCount(); i > 0; --i) {
    if (m_layers.getLayerID(i - 1) == layer) {
      result.push_back(i - 1);
    }
  }
  return result;
}

} // namespace Core
} // namespace Avogadro
