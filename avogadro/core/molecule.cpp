/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molecule.h"

#include "basisset.h"
#include "cube.h"
#include "elements.h"
#include "gaussianset.h"
#include "layermanager.h"
#include "mdlvalence_p.h"
#include "mesh.h"
#include "neighborperceiver.h"
#include "residue.h"
#include "slaterset.h"
#include "unitcell.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <iostream>
#include <utility>

namespace Avogadro::Core {

Molecule::Molecule()
  : m_basisSet(nullptr), m_unitCell(nullptr),
    m_layers(LayerManager::getMoleculeLayer(this))
{
  m_elements.reset();
}

Molecule::Molecule(const Molecule& other)
  : m_data(other.m_data), m_partialCharges(other.m_partialCharges),
    m_spectra(other.m_spectra), m_customElementMap(other.m_customElementMap),
    m_elements(other.m_elements), m_positions2d(other.m_positions2d),
    m_positions3d(other.m_positions3d), m_atomLabels(other.m_atomLabels),
    m_bondLabels(other.m_bondLabels), m_coordinates3d(other.m_coordinates3d),
    m_timesteps(other.m_timesteps), m_hybridizations(other.m_hybridizations),
    m_formalCharges(other.m_formalCharges),
    m_forceVectors(other.m_forceVectors), m_colors(other.m_colors),
    m_vibrationFrequencies(other.m_vibrationFrequencies),
    m_vibrationIRIntensities(other.m_vibrationIRIntensities),
    m_vibrationRamanIntensities(other.m_vibrationRamanIntensities),
    m_vibrationLx(other.m_vibrationLx), m_selectedAtoms(other.m_selectedAtoms),
    m_meshes(), m_cubes(),
    m_basisSet(other.m_basisSet ? other.m_basisSet->clone() : nullptr),
    m_unitCell(other.m_unitCell ? new UnitCell(*other.m_unitCell) : nullptr),
    m_residues(other.m_residues), m_hallNumber(other.m_hallNumber),
    m_constraints(other.m_constraints),
    m_frozenAtomMask(other.m_frozenAtomMask), m_graph(other.m_graph),
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

  // Make sure all the atoms are in the active layer
  if (other.m_layers.maxLayer() == 0) {
    for (Index i = 0; i < atomCount(); ++i)
      m_layers.addAtomToActiveLayer(i);
  }
}

void Molecule::readProperties(const Molecule& other)
{
  m_atomLabels = other.m_atomLabels;
  m_bondLabels = other.m_bondLabels;
  m_colors = other.m_colors;
  // merge data maps by iterating through other's map
  for (auto it = other.m_data.constBegin(); it != other.m_data.constEnd();
       ++it) {
    // even if we have the same key, we want to overwrite
    m_data.setValue(it->first, it->second);
  }
  // merge partial charge maps
  for (auto it = other.m_partialCharges.cbegin();
       it != other.m_partialCharges.cend(); ++it) {
    m_partialCharges[it->first] = it->second;
  }

  // copy spectra
  m_spectra = other.m_spectra;

  // copy orbital information
  SlaterSet* slaterSet = dynamic_cast<SlaterSet*>(other.m_basisSet);
  if (slaterSet != nullptr) {
    m_basisSet = slaterSet->clone();
    m_basisSet->setMolecule(this);
  }
  GaussianSet* gaussianSet = dynamic_cast<GaussianSet*>(other.m_basisSet);
  if (gaussianSet != nullptr) {
    m_basisSet = gaussianSet->clone();
    m_basisSet->setMolecule(this);
  }

  // copy over spectra information
  if (other.m_vibrationFrequencies.size() > 0) {
    m_vibrationFrequencies = other.m_vibrationFrequencies;
    m_vibrationIRIntensities = other.m_vibrationIRIntensities;
    m_vibrationRamanIntensities = other.m_vibrationRamanIntensities;
    m_vibrationLx = other.m_vibrationLx;
  }

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
  : m_data(other.m_data), m_partialCharges(std::move(other.m_partialCharges)),
    m_spectra(other.m_spectra),
    m_customElementMap(std::move(other.m_customElementMap)),
    m_elements(other.m_elements), m_positions2d(other.m_positions2d),
    m_positions3d(other.m_positions3d), m_atomLabels(other.m_atomLabels),
    m_bondLabels(other.m_bondLabels), m_coordinates3d(other.m_coordinates3d),
    m_timesteps(other.m_timesteps), m_hybridizations(other.m_hybridizations),
    m_formalCharges(other.m_formalCharges), m_colors(other.m_colors),
    m_vibrationFrequencies(other.m_vibrationFrequencies),
    m_vibrationIRIntensities(other.m_vibrationIRIntensities),
    m_vibrationRamanIntensities(other.m_vibrationRamanIntensities),
    m_vibrationLx(other.m_vibrationLx),
    m_selectedAtoms(std::move(other.m_selectedAtoms)),
    m_meshes(std::move(other.m_meshes)), m_cubes(std::move(other.m_cubes)),
    m_basisSet(std::exchange(other.m_basisSet, nullptr)),
    m_unitCell(std::exchange(other.m_unitCell, nullptr)),
    m_residues(other.m_residues), m_hallNumber(other.m_hallNumber),
    m_constraints(other.m_constraints),
    m_frozenAtomMask(other.m_frozenAtomMask), m_graph(other.m_graph),
    m_bondOrders(other.m_bondOrders), m_atomicNumbers(other.m_atomicNumbers),
    m_layers(LayerManager::getMoleculeLayer(this))
{
  // Copy the layers, only if they exist
  if (other.m_layers.maxLayer() > 0)
    m_layers = LayerManager::getMoleculeLayer(&other, this);
  else {
    // make sure all the atoms are in the active layer
    for (Index i = 0; i < atomCount(); ++i)
      m_layers.addAtomToActiveLayer(i);
  }
}

Molecule& Molecule::operator=(const Molecule& other)
{
  if (this != &other) {
    m_data = other.m_data;
    m_partialCharges = other.m_partialCharges;
    m_spectra = other.m_spectra;
    m_customElementMap = other.m_customElementMap;
    m_elements = other.m_elements;
    m_positions2d = other.m_positions2d;
    m_positions3d = other.m_positions3d;
    m_atomLabels = other.m_atomLabels;
    m_bondLabels = other.m_bondLabels;
    m_coordinates3d = other.m_coordinates3d;
    m_timesteps = other.m_timesteps;
    m_hybridizations = other.m_hybridizations;
    m_formalCharges = other.m_formalCharges;
    m_colors = other.m_colors,
    m_vibrationFrequencies = other.m_vibrationFrequencies;
    m_vibrationIRIntensities = other.m_vibrationIRIntensities;
    m_vibrationRamanIntensities = other.m_vibrationRamanIntensities;
    m_vibrationLx = other.m_vibrationLx;
    m_selectedAtoms = other.m_selectedAtoms;
    m_residues = other.m_residues;
    m_graph = other.m_graph;
    m_bondOrders = other.m_bondOrders;
    m_atomicNumbers = other.m_atomicNumbers;
    m_hallNumber = other.m_hallNumber;
    m_constraints = other.m_constraints;
    m_frozenAtomMask = other.m_frozenAtomMask;

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

    // Copy the layers, only if they exist
    if (other.m_layers.maxLayer() > 0)
      m_layers = LayerManager::getMoleculeLayer(&other, this);
    else {
      // make sure all the atoms are in the active layer
      for (Index i = 0; i < atomCount(); ++i)
        m_layers.addAtomToActiveLayer(i);
    }
  }

  return *this;
}

Molecule& Molecule::operator=(Molecule&& other) noexcept
{
  if (this != &other) {
    m_data = other.m_data;
    m_partialCharges = std::move(other.m_partialCharges);
    m_spectra = other.m_spectra;
    m_customElementMap = std::move(other.m_customElementMap);
    m_elements = other.m_elements;
    m_positions2d = other.m_positions2d;
    m_positions3d = other.m_positions3d;
    m_atomLabels = other.m_atomLabels;
    m_bondLabels = other.m_bondLabels;
    m_coordinates3d = other.m_coordinates3d;
    m_timesteps = other.m_timesteps;
    m_hybridizations = other.m_hybridizations;
    m_formalCharges = other.m_formalCharges;
    m_colors = other.m_colors;
    m_vibrationFrequencies = other.m_vibrationFrequencies;
    m_vibrationIRIntensities = other.m_vibrationIRIntensities;
    m_vibrationRamanIntensities = other.m_vibrationRamanIntensities;
    m_vibrationLx = other.m_vibrationLx;
    m_selectedAtoms = std::move(other.m_selectedAtoms);
    m_residues = other.m_residues;
    m_graph = other.m_graph;
    m_bondOrders = other.m_bondOrders;
    m_atomicNumbers = other.m_atomicNumbers;
    m_hallNumber = other.m_hallNumber;
    m_constraints = other.m_constraints;
    m_frozenAtomMask = other.m_frozenAtomMask;

    clearMeshes();
    m_meshes = std::move(other.m_meshes);

    clearCubes();
    m_cubes = std::move(other.m_cubes);

    delete m_basisSet;
    m_basisSet = std::exchange(other.m_basisSet, nullptr);

    delete m_unitCell;
    m_unitCell = std::exchange(other.m_unitCell, nullptr);

    // Copy the layers, if they exist
    if (other.m_layers.maxLayer() > 0)
      m_layers = LayerManager::getMoleculeLayer(&other, this);
    else {
      // make sure all the atoms are in the active layer
      for (Index i = 0; i < atomCount(); ++i)
        m_layers.addAtomToActiveLayer(i);
    }
  }

  return *this;
}

Molecule::~Molecule()
{
  // LayerManager::deleteMolecule(this);
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

void Molecule::setPartialCharges(const std::string& type, const MatrixX& value)
{
  if (static_cast<Index>(value.size()) != atomCount())
    return;

  m_partialCharges[type] = value;
}

MatrixX Molecule::partialCharges(const std::string& type) const
{
  auto search = m_partialCharges.find(type);
  if (search != m_partialCharges.end()) {
    return search->second; // value from the map
  } else {
    MatrixX charges(atomCount(), 1);
    charges.fill(0.0);
    return charges;
  }
}

std::set<std::string> Molecule::partialChargeTypes() const
{
  std::set<std::string> types;
  for (auto& it : m_partialCharges)
    types.insert(it.first);
  return types;
}

std::set<std::string> Molecule::spectraTypes() const
{
  std::set<std::string> types;
  for (auto& it : m_spectra)
    types.insert(it.first);
  return types;
}

void Molecule::setSpectra(const std::string& type, const MatrixX& value)
{
  m_spectra[type] = value;
}

MatrixX Molecule::spectra(const std::string& type) const
{
  MatrixX value;

  auto search = m_spectra.find(type);
  if (search != m_spectra.end()) {
    value = search->second; // value from the map
  }

  return value;
}

void Molecule::addConstraint(Real value, Index a, Index b, Index c, Index d)
{
  Constraint newConstraint(a, b, c, d, value);
  m_constraints.push_back(newConstraint);
}

void Molecule::removeConstraint(Index a, Index b, Index c, Index d)
{
  // loop through and remove if the constraint matches all atom indexes
  for (auto it = m_constraints.begin(); it != m_constraints.end();) {
    if (it->aIndex() == a && it->bIndex() == b && it->cIndex() == c &&
        it->dIndex() == d) {
      it = m_constraints.erase(it);
      return;
    } else
      ++it;
  }
}

void Molecule::setFrozenAtom(Index atomId, bool frozen)
{
  if (atomId >= m_atomicNumbers.size())
    return;

  Eigen::Index size = m_frozenAtomMask.rows();
  auto newSize = static_cast<Eigen::Index>(3 * m_atomicNumbers.size());

  if (m_frozenAtomMask.rows() != newSize)
    m_frozenAtomMask.conservativeResize(newSize);

  if (m_frozenAtomMask.rows() > size)
    for (Eigen::Index i = size; i < m_frozenAtomMask.rows(); ++i)
      m_frozenAtomMask[i] = 1.0f;

  float value = frozen ? 0.0f : 1.0f;
  auto base = static_cast<Eigen::Index>(atomId * 3);
  if (base <= m_frozenAtomMask.rows() - 3) {
    m_frozenAtomMask[base] = value;
    m_frozenAtomMask[base + 1] = value;
    m_frozenAtomMask[base + 2] = value;
  }
}

bool Molecule::frozenAtom(Index atomId) const
{
  auto base = static_cast<Eigen::Index>(atomId * 3);
  if (base <= m_frozenAtomMask.rows() - 3) {
    return (m_frozenAtomMask[base] == 0.0 &&
            m_frozenAtomMask[base + 1] == 0.0 &&
            m_frozenAtomMask[base + 2] == 0.0);
  }
  return false;
}

bool Molecule::frozenAtomAxis(Index atomId, int axis) const
{
  auto base = static_cast<Eigen::Index>(atomId * 3);
  if (base <= m_frozenAtomMask.rows() - 3) {
    return (m_frozenAtomMask[base + axis] == 0.0);
  }
  return false;
}

void Molecule::setFrozenAtomAxis(Index atomId, int axis, bool frozen)
{
  Eigen::Index size = m_frozenAtomMask.rows();
  auto newSize = static_cast<Eigen::Index>(3 * m_atomicNumbers.size());

  if (m_frozenAtomMask.rows() != newSize)
    m_frozenAtomMask.conservativeResize(newSize);

  if (m_frozenAtomMask.rows() > size)
    for (Eigen::Index i = size; i < m_frozenAtomMask.rows(); ++i)
      m_frozenAtomMask[i] = 1.0f;

  float value = frozen ? 0.0f : 1.0f;
  auto base = static_cast<Eigen::Index>(atomId * 3);
  if (axis >= 0 && axis < 3 && base <= m_frozenAtomMask.rows() - 3) {
    m_frozenAtomMask[base + axis] = value;
  }
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

signed char Molecule::totalCharge() const
{
  signed char charge = 0;

  // check the data map first
  if (m_data.hasValue("totalCharge")) {
    charge = m_data.value("totalCharge").toInt();
  } else if (m_formalCharges.size() > 0) {
    for (Index i = 0; i < m_formalCharges.size(); ++i)
      charge += m_formalCharges[i];
    return charge;
  }
  return charge; // should be zero
}

char Molecule::totalSpinMultiplicity() const
{
  char spin = 1;

  // check the data map first
  if (m_data.hasValue("totalSpinMultiplicity")) {
    spin = m_data.value("totalSpinMultiplicity").toInt();
  } else {
    // add up the electrons
    unsigned long electrons = 0;
    for (Index i = 0; i < m_atomicNumbers.size(); ++i)
      electrons += m_atomicNumbers[i];

    // adjust by the total charge
    electrons -= totalCharge();

    // if there are an even number of electrons, the spin is 1
    // if there are an odd number of electrons, the spin is 2
    // (might not be true, but a good default for many molecules)
    // %todo - adjust for inorganic / organometallics
    if (electrons % 2 == 0)
      spin = 1;
    else
      spin = 2;
  }

  return spin; // should be zero
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
  m_graph.addVertex();
  m_atomicNumbers.push_back(number);
  // we're not going to easily handle custom elements
  if (number < element_count)
    m_elements.set(number);
  else
    m_elements.set(element_count - 1); // custom element

  m_layers.addAtomToActiveLayer(atomCount() - 1);
  m_partialCharges.clear();
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
  // Allow Argument Dependent Lookup for swap
  using std::swap;

  m_graph.swapEdgeIndices(a, b);
  swap(m_bondOrders[a], m_bondOrders[b]);
}
void Molecule::swapAtom(Index a, Index b)
{
  // Allow Argument Dependent Lookup for swap
  using std::swap;

  Index max = a > b ? a : b;
  if (m_positions2d.size() > max)
    swap(m_positions2d[a], m_positions2d[b]);
  if (m_positions3d.size() > max)
    swap(m_positions3d[a], m_positions3d[b]);
  if (m_hybridizations.size() > max)
    swap(m_hybridizations[a], m_hybridizations[b]);
  if (m_formalCharges.size() > max)
    swap(m_formalCharges[a], m_formalCharges[b]);
  if (m_colors.size() > max)
    swap(m_colors[a], m_colors[b]);

  swap(m_atomicNumbers[a], m_atomicNumbers[b]);
  m_graph.swapVertexIndices(a, b);
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

  m_partialCharges.clear();
  removeBonds(index);

  // before we remove, check if there's any other atom of this element
  // (e.g., we removed the last oxygen)
  auto elementToRemove = m_atomicNumbers[index];
  bool foundAnother = false;
  for (Index i = 0; i < atomCount(); ++i) {
    if (i == index)
      continue;

    if (m_atomicNumbers[index] == elementToRemove) {
      foundAnother = true;
      break; // we're done
    }
  }
  if (!foundAnother)
    m_elements.reset(elementToRemove);

  m_atomicNumbers.swapAndPop(index);
  m_graph.removeVertex(index);

  m_layers.removeAtom(index);

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
  m_atomLabels.clear();
  m_hybridizations.clear();
  m_formalCharges.clear();
  m_colors.clear();
  m_atomicNumbers.clear();
  m_bondOrders.clear();
  m_bondLabels.clear();
  m_graph.clear();
  m_partialCharges.clear();
  m_elements.reset();
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
    m_graph.addEdge(atom1, atom2);
    m_bondOrders.push_back(order);
    index = static_cast<Index>(m_graph.edgeCount() - 1);
  } else {
    m_bondOrders[index] = order;
  }
  // any existing charges are invalidated
  m_partialCharges.clear();
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
  auto aux = static_cast<float>(n);
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
  m_graph.removeEdge(index);
  m_bondOrders.swapAndPop(index);
  m_partialCharges.clear();
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
  m_graph.removeEdges();
  m_graph.setSize(atomCount());
  m_partialCharges.clear();
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

  const std::vector<Index>& edgeIndices = m_graph.edges(atomId1);
  for (unsigned long index : edgeIndices) {
    const std::pair<Index, Index>& pair = m_graph.endpoints(index);
    if (pair.first == atomId2 || pair.second == atomId2)
      return BondType(const_cast<Molecule*>(this), index);
  }
  return BondType();
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
    const std::vector<Index>& edgeIndices = m_graph.edges(a);
    for (unsigned long index : edgeIndices) {
      if (m_graph.endpoints(index).first == a ||
          m_graph.endpoints(index).second == a) {
        // work around to consult bonds without breaking constantness
        atomBonds.push_back(new BondType(const_cast<Molecule*>(this), index));
      }
    }
  }

  std::sort(atomBonds.begin(), atomBonds.end(),
            [](const BondType*& ba, const BondType*& bb) {
              return ba->index() < bb->index();
            });
  return atomBonds;
}

Array<Molecule::BondType> Molecule::bonds(Index a)
{
  Array<BondType> atomBonds;
  if (a < atomCount()) {
    const std::vector<Index>& edgeIndices = m_graph.edges(a);
    for (unsigned long index : edgeIndices) {
      auto bond = bondPair(index);
      if (bond.first == a || bond.second == a)
        atomBonds.push_back(BondType(this, index));
    }
  }

  std::sort(atomBonds.begin(), atomBonds.end(),
            [](BondType& ba, BondType& bb) { return ba.index() < bb.index(); });
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

Array<double> Molecule::vibrationIRIntensities() const
{
  return m_vibrationIRIntensities;
}

void Molecule::setVibrationIRIntensities(const Array<double>& intensities)
{
  m_vibrationIRIntensities = intensities;
}

Array<double> Molecule::vibrationRamanIntensities() const
{
  return m_vibrationRamanIntensities;
}

void Molecule::setVibrationRamanIntensities(const Array<double>& intensities)
{
  m_vibrationRamanIntensities = intensities;
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

void Molecule::perceiveBondOrders()
{
  // check for coordinates and that there are some bonds
  if (m_positions3d.size() != atomCount() || m_positions3d.size() < 2 ||
      m_graph.edgeCount() == 0)
    return;

  // save the existing bonds and bond orders
  // first calculate the unsaturated valence for every atom
  Array<unsigned char> originalBonds = m_bondOrders;
  Array<unsigned char> unsaturatedValence(atomCount(), 0);
  bool anyUnsaturated = false;
  for (Index i = 0; i < atomCount(); ++i) {
    unsigned char boSum = 0;
    for (auto bond : bonds(i)) {
      boSum += bond.order();
    }
    unsaturatedValence[i] =
      atomValence(atomicNumber(i), formalCharge(i), bonds(i).size()) - boSum;

    if (unsaturatedValence[i] > 0)
      anyUnsaturated = true;
  }

  Index startIndex = 0;
  Index initialAtom = 0;
  while (anyUnsaturated) {

    // okay, we're first going to try placing *one* bond from our start atom
    // .. then we can try placing bonds anywhere

    // find the first atom with unsaturated valence of ONE
    bool foundStart = false;
    for (Index i = startIndex; i < atomCount(); ++i) {
      if (unsaturatedValence[i] == 1) {
        startIndex = i;
        foundStart = true;
        break;
      }
    }

    // if we didn't find an atom with unsaturated valence of ONE,
    // .. then find *something*
    if (!foundStart) {
      for (Index i = startIndex; i < atomCount(); ++i) {
        if (unsaturatedValence[i] > 0) {
          startIndex = i;
          foundStart = true;
          break;
        }
      }
    }

    if (foundStart) {
      // std::cerr << "Found start index " << startIndex << std::endl;

      // look at the neighbors of our start atom
      Index bestIndex = MaxIndex;
      unsigned bestValence = 256; // something impossible
      Real bestDistance = 100.0;  // 10 Angstroms squared
      Vector3 startPosition = m_positions3d[startIndex];
      // iterate through the Indexes of the neighbors
      for (auto neighbor : graph().neighbors(startIndex)) {
        // if this neighbor doesn't have an unsaturated valence, skip it
        if (unsaturatedValence[neighbor] == 0) {
          continue;
        }

        if (unsaturatedValence[neighbor] < bestValence) {
          bestIndex = neighbor;
          bestValence = unsaturatedValence[neighbor];
          bestDistance =
            (m_positions3d[neighbor] - startPosition).squaredNorm();
        } else if (unsaturatedValence[neighbor] == bestValence) {
          // check if this neighbor is closer
          Real distance =
            (m_positions3d[neighbor] - startPosition).squaredNorm();
          if (distance < bestDistance) {
            bestIndex = neighbor;
            bestDistance = distance;
          }
        }
      }
      // if we found a neighbor, then we can assign a bond order and update
      // charges
      if (bestIndex != MaxIndex) {
        /*std::cerr << "Assigning bond " << startIndex << " " << bestIndex
                  << std::endl; */

        // assign the bond order
        m_bondOrders[bond(startIndex, bestIndex).index()] += 1;
        // update the unsaturated valence of the start atom
        unsaturatedValence[startIndex] -= 1;
        // update the unsaturated valence of the neighbor atom
        unsaturatedValence[bestIndex] -= 1;

        startIndex = 0; // we can now try placing bonds anywhere
      } else {
        startIndex += 1;
      }
    }

    // TODO: update the current formal charges

    anyUnsaturated = false; // check if we're done
    for (Index i = 0; i < atomCount(); ++i) {
      if (unsaturatedValence[i] > 0) {
        anyUnsaturated = true;
        break;
      }
    }

    if (!foundStart && anyUnsaturated) {
      // we've gone through and it's not working
      // try a new starting atom and reset the bond orders
      // std::cerr << " didn't work " << initialAtom << std::endl;

      initialAtom += 1;
      startIndex = initialAtom;
      for (Index i = 0; i < m_bondOrders.size(); ++i) {
        unsigned change = m_bondOrders[i] - originalBonds[i];
        if (change > 0) {
          // update the valences
          unsaturatedValence[bond(i).atom1().index()] += change;
          unsaturatedValence[bond(i).atom2().index()] += change;
        }
        m_bondOrders[i] = originalBonds[i];
      }
    }

    if (initialAtom >= atomCount()) {
      break;
    }

  } // keep going until we've assigned all the bond orders
}

void Molecule::perceiveBondsSimple(const double tolerance, const double min)
{
  // check for coordinates
  if (m_positions3d.size() != atomCount() || m_positions3d.size() < 2)
    return;

  // cache atomic radii
  std::vector<double> radii(atomCount());
  double max_radius = 0.0;
  for (size_t i = 0; i < radii.size(); i++) {
    radii[i] = Elements::radiusCovalent(atomicNumber(i));
    if (radii[i] <= 0.0)
      radii[i] = 2.0;
    if (radii[i] > max_radius)
      max_radius = radii[i];
  }

  float maxDistance = 2.0 * max_radius + tolerance;
  auto neighborPerceiver = NeighborPerceiver(m_positions3d, maxDistance);

  // check for bonds
  // O(n) average-case, O(n^2) worst-case
  // note that the "worst case" here would need to be an invalid molecule
  Array<Index> neighbors;
  for (Index i = 0; i < atomCount(); i++) {
    Vector3 ipos = m_positions3d[i];
    neighborPerceiver.getNeighborsInclusiveInPlace(neighbors, ipos);
    for (unsigned long j : neighbors) {
      double cutoff = radii[i] + radii[j] + tolerance;
      Vector3 jpos = m_positions3d[j];
      Vector3 diff = jpos - ipos;

      // Don't automatically bond nobel gases to anything
      switch (atomicNumber(i)) {
        case 2:  // He
        case 10: // Ne
        case 18: // Ar
        case 36: // Kr
          continue;
        default:
          break;
      }

      // now for the other atom
      switch (atomicNumber(j)) {
        case 2:  // He
        case 10: // Ne
        case 18: // Ar
        case 36: // Kr
          continue;
        default:
          break;
      }

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
  for (auto& m_residue : m_residues) {
    m_residue.resolveResidueBonds(*this);
  }
}

size_t Molecule::coordinate3dCount() const
{
  return m_coordinates3d.size();
}

bool Molecule::setCoordinate3d(int coord)
{
  if (coord >= 0 && coord < static_cast<int>(m_coordinates3d.size())) {
    m_positions3d = m_coordinates3d[coord];
    return true;
  }
  return false;
}

void Molecule::clearCoordinate3d()
{
  m_coordinates3d.clear();
}

Array<Vector3> Molecule::coordinate3d(size_t index) const
{
  return m_coordinates3d[index];
}

bool Molecule::setCoordinate3d(const Array<Vector3>& coords, size_t index)
{
  if (m_coordinates3d.size() <= index)
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
    m_graph.editEdgeInPlace(bondId, pair.first, pair.second);
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
  for (unsigned char m_atomicNumber : m_atomicNumbers) {
    if (m_atomicNumber == number)
      ++count;
  }
  return count;
}

bool Molecule::setAtomicNumbers(const Core::Array<unsigned char>& nums)
{
  if (nums.size() == atomCount()) {
    m_atomicNumbers = nums;

    // update element mask
    m_elements.reset();
    // update colors too
    if (nums.size() == m_colors.size()) {
      for (Index i = 0; i < nums.size(); ++i) {
        m_colors[i] = Vector3ub(Elements::color(m_atomicNumbers[i]));
        m_elements.set(m_atomicNumbers[i]);
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

    // recalculate the element mask
    m_elements.reset();
    for (unsigned char m_atomicNumber : m_atomicNumbers) {
      m_elements.set(m_atomicNumber);
    }

    // update colors too
    if (atomId < m_colors.size())
      m_colors[atomId] = Vector3ub(Elements::color(number));

    return true;
  }
  return false;
}

bool Molecule::hasCustomElements() const
{
  for (unsigned char m_atomicNumber : m_atomicNumbers) {
    if (Core::isCustomElement(m_atomicNumber))
      return true;
  }
  return false;
}

std::map<unsigned char, size_t> Molecule::composition() const
{
  // A map of atomic symbols to their quantity.
  std::map<unsigned char, size_t> composition;
  for (unsigned char m_atomicNumber : m_atomicNumbers) {
    ++composition[m_atomicNumber];
  }
  return composition;
}

bool Molecule::removeBonds(Index atom)
{
  if (atom >= atomCount())
    return false;

  while (true) {
    const std::vector<size_t>& bondList = m_graph.edges(atom);
    if (!bondList.size())
      break;
    size_t bond = bondList[0];
    removeBond(bond);
  }
  return true;
}

Array<std::pair<Index, Index>> Molecule::getAtomBonds(Index index) const
{
  Array<std::pair<Index, Index>> result;
  const std::vector<Index>& edgeIndices = m_graph.edges(index);
  for (unsigned long edgeIndice : edgeIndices) {
    result.push_back(m_graph.endpoints(edgeIndice));
  }
  return result;
}

Array<unsigned char> Molecule::getAtomOrders(Index index) const
{
  Array<unsigned char> result;
  const std::vector<Index>& edgeIndices = m_graph.edges(index);
  for (unsigned long edgeIndice : edgeIndices) {
    result.push_back(m_bondOrders[edgeIndice]);
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

void Molecule::boundingBox(Vector3& boxMin, Vector3& boxMax,
                           const double radius) const
{
  boxMin.setConstant(std::numeric_limits<double>::max());
  boxMax.setConstant(-std::numeric_limits<double>::max());

  const bool noSelection = isSelectionEmpty();

  for (uint32_t i = 0; i < atomCount(); i++) {
    if (noSelection || m_selectedAtoms[i]) {

      const Vector3 boxMinBuffer = atom(i).position3d().array() - radius;
      const Vector3 boxMaxBuffer = atom(i).position3d().array() + radius;

      boxMin.x() = std::min(boxMinBuffer.x(), boxMin.x());
      boxMin.y() = std::min(boxMinBuffer.y(), boxMin.y());
      boxMin.z() = std::min(boxMinBuffer.z(), boxMin.z());

      boxMax.x() = std::max(boxMaxBuffer.x(), boxMax.x());
      boxMax.y() = std::max(boxMaxBuffer.y(), boxMax.y());
      boxMax.z() = std::max(boxMaxBuffer.z(), boxMax.z());
    }
  }
}

} // namespace Avogadro::Core
