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
#include <cmath>
#include <cstddef>
#include <cmath>
#include <iostream>
#include <memory>
#include <utility>

namespace Avogadro::Core {

Molecule::Molecule()
  : m_basisSet(nullptr), m_unitCell(nullptr),
    m_layerInfo(std::make_shared<MoleculeInfo>())
{
  m_elements.reset();
}

Molecule::Molecule(const Molecule& other)
  : m_data(other.m_data), m_partialCharges(other.m_partialCharges),
    m_spectra(other.m_spectra), m_atomProperties(other.m_atomProperties),
    m_bondProperties(other.m_bondProperties),
    m_residueProperties(other.m_residueProperties),
    m_conformerProperties(other.m_conformerProperties),
    m_customElementMap(other.m_customElementMap), m_elements(other.m_elements),
    m_positions2d(other.m_positions2d), m_positions3d(other.m_positions3d),
    m_atomLabels(other.m_atomLabels), m_bondLabels(other.m_bondLabels),
    m_residueLabels(other.m_residueLabels),
    m_coordinates3d(other.m_coordinates3d),
    m_coordinate3dIndex(other.m_coordinate3dIndex),
    m_velocities(other.m_velocities), m_timesteps(other.m_timesteps),
    m_hybridizations(other.m_hybridizations),
    m_formalCharges(other.m_formalCharges), m_isotopes(other.m_isotopes),
    m_forceVectors(other.m_forceVectors), m_colors(other.m_colors),
    m_vibrations(other.m_vibrations), m_selectedAtoms(other.m_selectedAtoms),
    m_meshes(), m_cubes(),
    m_basisSet(other.m_basisSet ? other.m_basisSet->clone() : nullptr),
    m_unitCell(other.m_unitCell ? new UnitCell(*other.m_unitCell) : nullptr),
    m_residues(other.m_residues), m_hallNumber(other.m_hallNumber),
    m_constraints(other.m_constraints),
    m_frozenAtomMask(other.m_frozenAtomMask), m_graph(other.m_graph),
    m_bondOrders(other.m_bondOrders), m_atomicNumbers(other.m_atomicNumbers),
    m_layerInfo(std::make_shared<MoleculeInfo>(other.ensureLayerInfo()))
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
  m_activeCubeIndex = other.m_activeCubeIndex;

  // Make sure all the atoms are in the active layer
  if (other.ensureLayerInfo().layer.maxLayer() == 0) {
    for (Index i = 0; i < atomCount(); ++i)
      ensureLayerInfo().layer.addAtomToActiveLayer(i);
  }
}

void Molecule::readProperties(const Molecule& other)
{
  m_atomLabels = other.m_atomLabels;
  m_bondLabels = other.m_bondLabels;
  m_residueLabels = other.m_residueLabels;
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

  // merge custom property maps
  m_atomProperties = other.m_atomProperties;
  m_bondProperties = other.m_bondProperties;
  m_residueProperties = other.m_residueProperties;
  m_conformerProperties = other.m_conformerProperties;

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
  if (!other.m_vibrations.empty())
    m_vibrations = other.m_vibrations;

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
    m_partialCharges(std::move(other.m_partialCharges)),
    m_spectra(std::move(other.m_spectra)),
    m_atomProperties(std::move(other.m_atomProperties)),
    m_bondProperties(std::move(other.m_bondProperties)),
    m_residueProperties(std::move(other.m_residueProperties)),
    m_conformerProperties(std::move(other.m_conformerProperties)),
    m_customElementMap(std::move(other.m_customElementMap)),
    m_elements(other.m_elements), m_positions2d(other.m_positions2d),
    m_positions3d(other.m_positions3d), m_atomLabels(other.m_atomLabels),
    m_bondLabels(other.m_bondLabels), m_residueLabels(other.m_residueLabels),
    m_coordinates3d(other.m_coordinates3d),
    m_coordinate3dIndex(std::exchange(other.m_coordinate3dIndex, 0)),
    m_velocities(other.m_velocities), m_timesteps(other.m_timesteps),
    m_hybridizations(other.m_hybridizations),
    m_formalCharges(other.m_formalCharges), m_isotopes(other.m_isotopes),
    m_forceVectors(other.m_forceVectors), m_colors(other.m_colors),
    m_vibrations(std::move(other.m_vibrations)),
    m_selectedAtoms(std::move(other.m_selectedAtoms)),
    m_meshes(std::move(other.m_meshes)), m_cubes(std::move(other.m_cubes)),
    m_activeCubeIndex(std::exchange(other.m_activeCubeIndex, 0)),
    m_basisSet(std::exchange(other.m_basisSet, nullptr)),
    m_unitCell(std::exchange(other.m_unitCell, nullptr)),
    m_residues(other.m_residues), m_hallNumber(other.m_hallNumber),
    m_constraints(std::move(other.m_constraints)),
    m_frozenAtomMask(std::move(other.m_frozenAtomMask)),
    m_graph(std::move(other.m_graph)), m_bondOrders(other.m_bondOrders),
    m_atomicNumbers(other.m_atomicNumbers),
    m_layerInfo(std::move(other.m_layerInfo))
{
  // Leave the moved-from molecule with no layer state rather than sharing
  // ours: sharing would let a write through the moved-from object reach this
  // one. It recreates its own on first use, which keeps this constructor
  // allocation-free and so honestly noexcept.
  other.m_layerInfo.reset();
}

Molecule& Molecule::operator=(const Molecule& other)
{
  if (this != &other) {
    m_data = other.m_data;
    m_partialCharges = other.m_partialCharges;
    m_spectra = other.m_spectra;
    m_atomProperties = other.m_atomProperties;
    m_bondProperties = other.m_bondProperties;
    m_residueProperties = other.m_residueProperties;
    m_conformerProperties = other.m_conformerProperties;
    m_customElementMap = other.m_customElementMap;
    m_elements = other.m_elements;
    m_positions2d = other.m_positions2d;
    m_positions3d = other.m_positions3d;
    m_atomLabels = other.m_atomLabels;
    m_bondLabels = other.m_bondLabels;
    m_residueLabels = other.m_residueLabels;
    m_coordinates3d = other.m_coordinates3d;
    m_coordinate3dIndex = other.m_coordinate3dIndex;
    m_velocities = other.m_velocities;
    m_timesteps = other.m_timesteps;
    m_hybridizations = other.m_hybridizations;
    m_formalCharges = other.m_formalCharges;
    m_isotopes = other.m_isotopes;
    m_forceVectors = other.m_forceVectors;
    m_colors = other.m_colors;
    m_vibrations = other.m_vibrations;
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
    m_activeCubeIndex = other.m_activeCubeIndex;

    delete m_basisSet;
    m_basisSet = other.m_basisSet ? other.m_basisSet->clone() : nullptr;
    delete m_unitCell;
    m_unitCell = other.m_unitCell ? new UnitCell(*other.m_unitCell) : nullptr;

    // Assign into the existing MoleculeInfo rather than replacing the handle,
    // so anything already sharing it (an undo command, say) sees the update.
    ensureLayerInfo() = other.ensureLayerInfo();
  }

  return *this;
}

Molecule& Molecule::operator=(Molecule&& other) noexcept
{
  if (this != &other) {
    m_data = std::move(other.m_data);
    m_partialCharges = std::move(other.m_partialCharges);
    m_spectra = std::move(other.m_spectra);
    m_atomProperties = std::move(other.m_atomProperties);
    m_bondProperties = std::move(other.m_bondProperties);
    m_residueProperties = std::move(other.m_residueProperties);
    m_conformerProperties = std::move(other.m_conformerProperties);
    m_customElementMap = std::move(other.m_customElementMap);
    m_elements = other.m_elements;
    m_positions2d = other.m_positions2d;
    m_positions3d = other.m_positions3d;
    m_atomLabels = other.m_atomLabels;
    m_bondLabels = other.m_bondLabels;
    m_residueLabels = other.m_residueLabels;
    m_coordinates3d = other.m_coordinates3d;
    m_coordinate3dIndex = other.m_coordinate3dIndex;
    m_velocities = other.m_velocities;
    m_timesteps = other.m_timesteps;
    m_hybridizations = other.m_hybridizations;
    m_formalCharges = other.m_formalCharges;
    m_isotopes = other.m_isotopes;
    m_forceVectors = other.m_forceVectors;
    m_colors = other.m_colors;
    m_vibrations = std::move(other.m_vibrations);
    m_selectedAtoms = std::move(other.m_selectedAtoms);
    m_residues = other.m_residues;
    m_graph = std::move(other.m_graph);
    m_bondOrders = other.m_bondOrders;
    m_atomicNumbers = other.m_atomicNumbers;
    m_hallNumber = other.m_hallNumber;
    m_constraints = std::move(other.m_constraints);
    m_frozenAtomMask = std::move(other.m_frozenAtomMask);

    clearMeshes();
    m_meshes = std::move(other.m_meshes);

    clearCubes();
    m_cubes = std::move(other.m_cubes);
    m_activeCubeIndex = other.m_activeCubeIndex;

    delete m_basisSet;
    m_basisSet = std::exchange(other.m_basisSet, nullptr);

    delete m_unitCell;
    m_unitCell = std::exchange(other.m_unitCell, nullptr);

    // Assign into the existing MoleculeInfo where there is one, so anything
    // already sharing it (an undo command, say) sees the update. Taking the
    // handle is the fallback, and neither path allocates.
    if (m_layerInfo && other.m_layerInfo)
      *m_layerInfo = std::move(*other.m_layerInfo);
    else
      m_layerInfo = std::move(other.m_layerInfo);
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
  return ensureLayerInfo().layer;
}
const Layer& Molecule::layer() const
{
  return ensureLayerInfo().layer;
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

PropertyMap& Molecule::atomProperties()
{
  return m_atomProperties;
}

const PropertyMap& Molecule::atomProperties() const
{
  return m_atomProperties;
}

PropertyMap& Molecule::bondProperties()
{
  return m_bondProperties;
}

const PropertyMap& Molecule::bondProperties() const
{
  return m_bondProperties;
}

PropertyMap& Molecule::residueProperties()
{
  return m_residueProperties;
}

const PropertyMap& Molecule::residueProperties() const
{
  return m_residueProperties;
}

PropertyMap& Molecule::conformerProperties()
{
  return m_conformerProperties;
}

const PropertyMap& Molecule::conformerProperties() const
{
  return m_conformerProperties;
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
  // Remove all constraints matching the atoms, regardless of ordering
  m_constraints.erase(
    std::remove_if(m_constraints.begin(), m_constraints.end(),
                   [a, b, c, d](const Constraint& constraint) {
                     return constraint.matches(a, b, c, d);
                   }),
    m_constraints.end());
}

namespace {

// The key the scan coordinates travel under, both in the property map and in
// CJSON's "properties" object.
const char* scanCoordinateKey = "scanCoordinates";

// Atom indices travel as doubles here, and MaxIndex has no exact double
// representation, so "no atom" is written as -1 instead.
double indexToValue(Index index)
{
  return (index == MaxIndex) ? -1.0 : static_cast<double>(index);
}

Index valueToIndex(double value)
{
  // -1 is the "no atom" sentinel; everything else has to be a whole number an
  // Index can hold. Above 2^53 a double cannot represent consecutive integers
  // at all, so nothing that large is a meaningful atom index.
  constexpr double maxExactInteger = 9007199254740992.0; // 2^53
  // Both comparisons are written so that NaN, which compares false against
  // everything, and infinity fail them rather than reaching the cast below,
  // where they would be undefined behaviour.
  if (!(value >= 0.0) || !(value <= maxExactInteger))
    return MaxIndex;

  // A fractional value did not come from setScanCoordinates(), so rounding it
  // would silently measure some unrelated atom. Reject it instead.
  if (value != std::floor(value))
    return MaxIndex;

  return static_cast<Index>(value);
}

bool sameAtoms(const Constraint& a, const Constraint& b)
{
  return a.aIndex() == b.aIndex() && a.bIndex() == b.bIndex() &&
         a.cIndex() == b.cIndex() && a.dIndex() == b.dIndex();
}

} // namespace

std::vector<Constraint> Molecule::scanCoordinates() const
{
  std::vector<Constraint> coordinates;
  if (!hasData(scanCoordinateKey))
    return coordinates;

  const Variant stored = data(scanCoordinateKey);
  if (stored.type() != Variant::Matrix)
    return coordinates;

  const MatrixX& matrix = stored.toMatrixRef();
  if (matrix.cols() < 2)
    return coordinates;

  for (Eigen::Index row = 0; row < matrix.rows(); ++row) {
    const Index a = valueToIndex(matrix(row, 0));
    const Index b = valueToIndex(matrix(row, 1));
    // Anything shorter than a distance is not a coordinate at all.
    if (a == MaxIndex || b == MaxIndex)
      continue;

    const Index c =
      (matrix.cols() > 2) ? valueToIndex(matrix(row, 2)) : MaxIndex;
    const Index d =
      (matrix.cols() > 3) ? valueToIndex(matrix(row, 3)) : MaxIndex;
    // A torsion cannot be missing its third atom.
    if (c == MaxIndex && d != MaxIndex)
      continue;

    coordinates.emplace_back(a, b, c, d);
  }

  return coordinates;
}

void Molecule::setScanCoordinates(const std::vector<Constraint>& coordinates)
{
  // One row per coordinate, always four columns: the reader cannot handle
  // rows of different lengths, and padding is cheaper than a second key.
  MatrixX matrix(static_cast<Eigen::Index>(coordinates.size()), 4);
  for (size_t i = 0; i < coordinates.size(); ++i) {
    const auto row = static_cast<Eigen::Index>(i);
    matrix(row, 0) = indexToValue(coordinates[i].aIndex());
    matrix(row, 1) = indexToValue(coordinates[i].bIndex());
    matrix(row, 2) = indexToValue(coordinates[i].cIndex());
    matrix(row, 3) = indexToValue(coordinates[i].dIndex());
  }

  setData(scanCoordinateKey, matrix);
}

void Molecule::addScanCoordinate(const Constraint& coordinate)
{
  std::vector<Constraint> coordinates = scanCoordinates();
  for (const auto& existing : coordinates) {
    if (sameAtoms(existing, coordinate))
      return;
  }

  coordinates.push_back(coordinate);
  setScanCoordinates(coordinates);
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

Array<unsigned short>& Molecule::isotopes()
{
  return m_isotopes;
}

const Array<unsigned short>& Molecule::isotopes() const
{
  return m_isotopes;
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

  ensureLayerInfo().layer.addAtomToActiveLayer(atomCount() - 1);
  // The calculated results are per-atom, so a new atom invalidates them just
  // as a removed atom does (see removeAtom()).
  clearCalculatedResults();
  m_atomProperties.addEntry();
  return AtomType(this, static_cast<Index>(atomCount() - 1));
}

Molecule::AtomType Molecule::addAtom(unsigned char number, Vector3 position3d)
{
  if (m_positions3d.size() == atomCount()) {
    m_positions3d.push_back(position3d);
  }
  return addAtom(number); // Use virtual dispatch
}

namespace {

// Every member touched below is indexed by atom, kept in step with
// m_atomicNumbers and m_graph. Molecule::swapAtom(), Molecule::removeAtom(),
// and Molecule::clearAtoms() must each handle every atom-indexed member: a
// member that is added to the class but missed in one of the three is a
// real bug (e.g. a label silently ending up on the wrong atom after a
// removal). The helpers below let each member cost one line per function,
// so the three function bodies can be written as parallel lists and a
// member missing from one of them is visible by inspection. When a new
// atom-indexed member is added to Molecule, add it to all three.
//
// "Handle" is not always "reindex". swapAtom() reindexes everything, since
// swapping two indices relabels the same structure. removeAtom() changes the
// structure, so anything computed *from* the structure -- forces, velocities,
// normal modes, partial charges -- is dropped there instead; see the comment
// in removeAtom(). Deciding which of the two a new member is, is the part
// that needs thought.
//
// A member does not have to be atom-indexed to hold an atom index, and those
// are the ones this list is apt to miss. m_residues is residue-indexed but
// the Atom proxies in its name maps store atom indices; m_constraints names
// up to four atoms per constraint; and m_basisSet records the atom each basis
// function is centred on. All three need reindexing all the same, and
// swapAtom() handles them explicitly at its end. So do the scan coordinates,
// which name atoms as constraints do but live in the property map rather than
// in a member of their own. removeAtom() handles the constraints and the scan
// coordinates too, dropping an entry that loses an atom rather than reindexing
// it, and clearAtoms() clears both.
//
// One is still unhandled, and needs a decision rather than a mechanical
// remap: m_residues in removeAtom(). Dropping a hydrogen from a residue is
// just an erase, but dropping a backbone atom arguably invalidates the
// residue altogether, and that is a chemistry question.

// Plain Array<T>, one entry per atom. An optional array can be shorter than
// atomCount() -- an atom added after the array was last set has no entry --
// so a swap has three cases: both atoms have an entry (plain swap); only the
// lower index does (grow to cover the higher index, filling the new tail by
// calling fill() for each newly-covered atom, indexed in the pre-swap
// numbering, so the data travels with its atom instead of being stranded);
// or neither does (nothing to do). @p fill lets callers whose T() is not a
// sensible default -- an Eigen fixed-size vector is left uninitialized by
// T(), not zeroed -- supply the right value instead; the overload below
// covers the common case where T() is fine.
template <typename T, typename Fill>
void swapAtomEntry(Array<T>& values, Index a, Index b, Index max, Fill fill)
{
  using std::swap;
  const Index lo = a < b ? a : b;
  if (values.size() > max) {
    swap(values[a], values[b]);
  } else if (values.size() > lo) {
    for (Index i = values.size(); i <= max; ++i)
      values.push_back(fill(i));
    swap(values[a], values[b]);
  }
}

template <typename T>
void swapAtomEntry(Array<T>& values, Index a, Index b, Index max)
{
  swapAtomEntry(values, a, b, max, [](Index) { return T(); });
}

// Same three cases as swapAtomEntry(), but for a swap-and-pop removal: if the
// array covers every atom it reindexes exactly like the required members
// do; if it is short but still reaches index, the atom swapped into index
// (the former last atom) has no entry of its own, so the stale value at
// index is reset by calling fill() for that atom -- atomCount() - 1, in the
// pre-removal numbering -- rather than left behind; otherwise index was
// never covered and there is nothing to do. See swapAtomEntry() above for
// why @p fill exists instead of always using T().
template <typename T, typename Fill>
void removeAtomEntry(Array<T>& values, Index index, Index atomCount, Fill fill)
{
  if (values.size() == atomCount) {
    values.swapAndPop(index);
  } else if (index < values.size()) {
    values[index] = fill(atomCount - 1);
  }
}

template <typename T>
void removeAtomEntry(Array<T>& values, Index index, Index atomCount)
{
  removeAtomEntry(values, index, atomCount, [](Index) { return T(); });
}

// Nested Array<Array<T>>: the outer index is a conformer/trajectory frame
// or a normal mode, the inner index is one entry per atom. Frames may
// legitimately be empty or a different length than atomCount() (e.g. not
// yet populated), so each frame is guarded individually rather than
// assuming they all match, using the same rule -- and the same @p fill
// parameter -- as swapAtomEntry()/removeAtomEntry() above.
template <typename T, typename Fill>
void swapAtomEntryFrames(Array<Array<T>>& frames, Index a, Index b, Index max,
                         Fill fill)
{
  using std::swap;
  const Index lo = a < b ? a : b;
  for (auto& frame : frames) {
    if (frame.size() > max) {
      swap(frame[a], frame[b]);
    } else if (frame.size() > lo) {
      for (Index i = frame.size(); i <= max; ++i)
        frame.push_back(fill(i));
      swap(frame[a], frame[b]);
    }
  }
}

template <typename T>
void swapAtomEntryFrames(Array<Array<T>>& frames, Index a, Index b, Index max)
{
  swapAtomEntryFrames(frames, a, b, max, [](Index) { return T(); });
}

template <typename T, typename Fill>
void removeAtomEntryFrames(Array<Array<T>>& frames, Index index,
                           Index atomCount, Fill fill)
{
  for (auto& frame : frames) {
    if (frame.size() == atomCount) {
      frame.swapAndPop(index);
    } else if (index < frame.size()) {
      frame[index] = fill(atomCount - 1);
    }
  }
}

template <typename T>
void removeAtomEntryFrames(Array<Array<T>>& frames, Index index,
                           Index atomCount)
{
  removeAtomEntryFrames(frames, index, atomCount, [](Index) { return T(); });
}

// std::vector<bool>, one entry per atom. std::swap() on the vector<bool>
// proxy reference is a well-known trap, so swap the two values explicitly.
void swapAtomEntry(std::vector<bool>& values, Index a, Index b, Index max)
{
  // Same three cases as the Array<T> overload above.
  const Index lo = a < b ? a : b;
  if (values.size() <= lo)
    return;
  if (values.size() <= max)
    values.resize(max + 1, false);
  bool temp = values[a];
  values[a] = values[b];
  values[b] = temp;
}

// Eigen::VectorXd storing 3 entries (x, y, z) per atom, as used by
// m_frozenAtomMask. Same three-way split as swapAtomEntry(): rows() is
// tracked in atom units (rows()/3) since each atom occupies 3 rows.
void swapAtomMaskEntry(Eigen::VectorXd& values, Index a, Index b, Index max)
{
  auto ea = static_cast<Eigen::Index>(a);
  auto eb = static_cast<Eigen::Index>(b);
  auto lo = static_cast<Eigen::Index>(a < b ? a : b);
  if (values.rows() >= static_cast<Eigen::Index>(3 * (max + 1))) {
    for (Eigen::Index i = 0; i < 3; ++i)
      std::swap(values[3 * ea + i], values[3 * eb + i]);
  } else if (values.rows() > 3 * lo) {
    // The atom at lo has a mask entry; the one at hi does not yet. Grow so
    // the mask travels with its atom, filling the new rows with "not
    // frozen" -- the same default setFrozenAtom() gives a newly-covered
    // atom -- then swap.
    const Eigen::Index oldRows = values.rows();
    values.conservativeResize(static_cast<Eigen::Index>(3 * (max + 1)));
    for (Eigen::Index i = oldRows; i < values.rows(); ++i)
      values[i] = 1.0;
    for (Eigen::Index i = 0; i < 3; ++i)
      std::swap(values[3 * ea + i], values[3 * eb + i]);
  }
}

void removeAtomMaskEntry(Eigen::VectorXd& values, Index index, Index atomCount)
{
  auto eIndex = static_cast<Eigen::Index>(index);
  if (values.rows() == static_cast<Eigen::Index>(3 * atomCount)) {
    Eigen::Index last = values.rows() - 3;
    for (Eigen::Index i = 0; i < 3; ++i)
      values[3 * eIndex + i] = values[last + i];
    values.conservativeResize(values.rows() - 3);
  } else if (values.rows() > 3 * eIndex) {
    // The atom swapped into index (the former last atom) has no mask entry
    // of its own, i.e. it is not frozen -- see the growth case above.
    for (Eigen::Index i = 0; i < 3; ++i)
      values[3 * eIndex + i] = 1.0;
  }
}

// Normal mode displacements, keyed by conformer. Each conformer holds one
// Array<Vector3> per mode, and those inner arrays are indexed by atom.
void swapAtomEntryVibrations(std::map<size_t, Molecule::VibrationData>& vibs,
                             Index a, Index b, Index max)
{
  for (auto& entry : vibs)
    swapAtomEntryFrames(entry.second.lx, a, b, max,
                        [](Index) { return Vector3::Zero(); });
}

// std::map<std::string, MatrixX>: one per-atom charge column per model.
// removeAtom() deliberately clears this map instead of reindexing it, since
// removing an atom invalidates any cached partial charges anyway.
void swapAtomEntry(std::map<std::string, MatrixX>& models, Index a, Index b,
                   Index max)
{
  using std::swap;
  for (auto& model : models) {
    if (static_cast<Index>(model.second.size()) > max)
      swap(model.second(static_cast<Eigen::Index>(a), 0),
           model.second(static_cast<Eigen::Index>(b), 0));
  }
}

// Bond-indexed counterpart of swapAtomEntry()/removeAtomEntry() above, same
// ragged-array rule, used for m_bondLabels: it may be shorter than
// bondCount() (a bond added after labels were last set has no entry), so
// removeBond()'s swap-and-pop and swapBond() have to treat a short entry as
// "no label" rather than silently attaching it to the wrong bond.
template <typename T>
void swapBondEntry(Array<T>& values, Index a, Index b, Index max)
{
  using std::swap;
  const Index lo = a < b ? a : b;
  if (values.size() > max) {
    swap(values[a], values[b]);
  } else if (values.size() > lo) {
    values.resize(max + 1, T());
    swap(values[a], values[b]);
  }
}

template <typename T>
void removeBondEntry(Array<T>& values, Index index, Index bondCount)
{
  if (values.size() == bondCount) {
    values.swapAndPop(index);
  } else if (index < values.size()) {
    values[index] = T();
  }
}

// Constraints and scan coordinates both name up to four atoms by index, so
// both follow the same rule when those atoms move. @p reindex maps an old atom
// index to its new one, or to MaxIndex for an atom that is going away; an
// entry that loses an atom is dropped rather than shortened, since a torsion
// becoming an angle is a different thing than the one that was asked for.
// swapAtom() only relabels, so nothing is dropped there; removeAtom() does
// both.
template <typename Reindex>
void remapAtomReferences(std::vector<Constraint>& entries, Reindex reindex)
{
  for (auto it = entries.begin(); it != entries.end();) {
    const Index a = reindex(it->aIndex());
    const Index b = reindex(it->bIndex());
    const Index c = reindex(it->cIndex());
    const Index d = reindex(it->dIndex());

    // An unused reference is MaxIndex before and after, so comparing against
    // the old value is what separates "was never set" from "just lost its
    // atom".
    if (a == MaxIndex || b == MaxIndex ||
        (c == MaxIndex && it->cIndex() != MaxIndex) ||
        (d == MaxIndex && it->dIndex() != MaxIndex)) {
      it = entries.erase(it);
      continue;
    }

    // set() keeps the force constant and re-infers only a type that was not
    // set explicitly, and that inference asks which references are MaxIndex --
    // which this cannot have changed.
    it->set(a, b, c, d, it->value());
    ++it;
  }
}

// The scan coordinates live in the property map rather than in a member, so
// they are read out, remapped by the same rule, and written back.
template <typename Reindex>
void remapScanCoordinates(Molecule& molecule, Reindex reindex)
{
  std::vector<Constraint> coordinates = molecule.scanCoordinates();
  if (coordinates.empty())
    return;

  remapAtomReferences(coordinates, reindex);
  molecule.setScanCoordinates(coordinates);
}

} // namespace

void Molecule::swapBond(Index a, Index b)
{
  // See swapEdgeIndices(): the callers are undo commands holding indices from
  // before the edit they reverse, so an index can name a bond that no longer
  // exists. m_bondOrders would be indexed out of bounds below.
  if (a >= bondCount() || b >= bondCount())
    return;

  // Allow Argument Dependent Lookup for swap
  using std::swap;

  m_graph.swapEdgeIndices(a, b);
  swap(m_bondOrders[a], m_bondOrders[b]);
  m_bondProperties.swapEntries(a, b, bondCount());
  swapBondEntry(m_bondLabels, a, b, a > b ? a : b);
}

void Molecule::swapAtom(Index a, Index b)
{
  // As in swapBond(): a stale index from an undo command must not reach the
  // atom-indexed arrays below.
  if (a >= atomCount() || b >= atomCount())
    return;

  Index max = a > b ? a : b;

  // Atom-indexed members -- see the comment above the helpers in the
  // anonymous namespace at the top of this file. Keep this list parallel
  // with removeAtom() and clearAtoms().
  swapAtomEntry(m_positions2d, a, b, max,
                [](Index) { return Vector2::Zero(); });
  swapAtomEntry(m_positions3d, a, b, max,
                [](Index) { return Vector3::Zero(); });
  swapAtomEntry(m_atomLabels, a, b, max);
  swapAtomEntry(m_hybridizations, a, b, max);
  swapAtomEntry(m_formalCharges, a, b, max);
  swapAtomEntry(m_isotopes, a, b, max);
  swapAtomEntry(m_forceVectors, a, b, max,
                [](Index) { return Vector3::Zero(); });
  swapAtomEntry(m_colors, a, b, max, [this](Index i) {
    return Vector3ub(Elements::color(m_atomicNumbers[i]));
  });
  swapAtomEntry(m_selectedAtoms, a, b, max);
  swapAtomEntryFrames(m_coordinates3d, a, b, max,
                      [](Index) { return Vector3::Zero(); });
  swapAtomEntryFrames(m_velocities, a, b, max,
                      [](Index) { return Vector3::Zero(); });
  swapAtomEntryVibrations(m_vibrations, a, b, max);
  swapAtomMaskEntry(m_frozenAtomMask, a, b, max);
  swapAtomEntry(m_partialCharges, a, b, max);

  // Allow Argument Dependent Lookup for swap
  using std::swap;
  swap(m_atomicNumbers[a], m_atomicNumbers[b]);
  m_graph.swapVertexIndices(a, b);
  ensureLayerInfo().layer.swapLayer(a, b);
  m_atomProperties.swapEntries(a, b, atomCount());

  // Residues are not an atom-indexed member and so are reached by none of the
  // helpers above: the array is residue-indexed, and it is the Atom proxies
  // inside each residue's name map that carry an atom index. Left alone, a
  // residue's atom names go on pointing at indices that now hold different
  // atoms -- the residue silently adopts its neighbours.
  for (auto& residue : m_residues) {
    for (auto& entry : residue.atomNameMap()) {
      const Index index = entry.second.index();
      if (index == a)
        entry.second = AtomType(entry.second.molecule(), b);
      else if (index == b)
        entry.second = AtomType(entry.second.molecule(), a);
    }
  }

  // Constraints are not atom-indexed either, but each names up to four atoms
  // by index. Unused references are MaxIndex, which never matches a real
  // atom, so they are left alone. Constraint::set() re-infers a cached type
  // that was not set explicitly, and that inference only asks which indices
  // are MaxIndex -- something a swap cannot change.
  auto reindex = [a, b](Index index) {
    if (index == a)
      return b;
    if (index == b)
      return a;
    return index;
  };
  remapAtomReferences(m_constraints, reindex);
  remapScanCoordinates(*this, reindex);

  // A basis set records which atom each basis function is centred on. Only
  // those recorded indices move: the basis functions keep their order, so
  // molecular orbital coefficients, which are indexed by basis function,
  // remain valid.
  if (m_basisSet != nullptr)
    m_basisSet->swapAtomIndices(a, b);
}

bool Molecule::removeAtom(Index index)
{
  if (index >= atomCount())
    return false;

  // Atom-indexed members -- see the comment above the helpers in the
  // anonymous namespace at the top of this file. Keep this list parallel
  // with swapAtom() and clearAtoms(). These must all run before
  // m_atomicNumbers (and therefore atomCount()) is updated below.
  removeAtomEntry(m_positions2d, index, atomCount(),
                  [](Index) { return Vector2::Zero(); });
  removeAtomEntry(m_positions3d, index, atomCount(),
                  [](Index) { return Vector3::Zero(); });
  removeAtomEntry(m_atomLabels, index, atomCount());
  removeAtomEntry(m_hybridizations, index, atomCount());
  removeAtomEntry(m_formalCharges, index, atomCount());
  removeAtomEntry(m_isotopes, index, atomCount());
  removeAtomEntry(m_colors, index, atomCount(), [this](Index i) {
    return Vector3ub(Elements::color(m_atomicNumbers[i]));
  });
  removeAtomEntryFrames(m_coordinates3d, index, atomCount(),
                        [](Index) { return Vector3::Zero(); });
  removeAtomMaskEntry(m_frozenAtomMask, index, atomCount());

  if (m_selectedAtoms.size() == atomCount()) {
    // swap and pop on std::vector<bool>
    if (index != m_selectedAtoms.size() - 1) {
      m_selectedAtoms[index] = m_selectedAtoms.back();
    }
    m_selectedAtoms.pop_back();
  } else if (index < m_selectedAtoms.size()) {
    // The former last atom has no entry, so it is not selected.
    m_selectedAtoms[index] = false;
  }

  // Constraints and scan coordinates name atoms by index without being
  // atom-indexed themselves, so neither the helpers above nor atomCount()
  // changing below reaches them, and both have to be handled while atomCount()
  // still describes the old molecule. The atom being removed is gone; the last
  // atom follows it into the hole that swap-and-pop leaves below, or whatever
  // named it would silently name the atom that lands there instead.
  const Index lastAtom = atomCount() - 1;
  auto follow = [index, lastAtom](Index atom) {
    if (atom == index)
      return MaxIndex;
    if (atom == lastAtom)
      return index;
    return atom;
  };

  remapAtomReferences(m_constraints, follow);
  remapScanCoordinates(*this, follow);

  // Losing an atom makes this a different molecule, so anything calculated
  // from the old one goes rather than being reindexed. Contrast the members
  // above, which are either the structure itself or user state about it
  // (labels, colours, selection, frozen atoms) and do follow their atoms.
  //
  // swapAtom() reindexes instead, and is right to: swapping two indices
  // relabels the same structure rather than changing it.
  clearCalculatedResults();
  m_atomProperties.removeEntry(index, atomCount());
  removeBonds(index);

  // before we remove, check if there's any other atom of this element
  // (e.g., we removed the last oxygen). Custom elements share a single bit
  // (element_count - 1, the same clamp addAtom() applies -- see the comment
  // there), so the bit to test/reset has to be the clamped one: comparing or
  // resetting the raw atomic number would throw for a custom element (out of
  // range for m_elements) and would miss that a different custom element
  // still holds that bit.
  auto elementBit = [](unsigned char number) {
    return number < element_count
             ? number
             : static_cast<unsigned char>(element_count - 1);
  };
  const unsigned char bitToRemove = elementBit(m_atomicNumbers[index]);
  bool foundAnother = false;
  for (Index i = 0; i < atomCount(); ++i) {
    if (i == index)
      continue;

    if (elementBit(m_atomicNumbers[i]) == bitToRemove) {
      foundAnother = true;
      break; // we're done
    }
  }
  if (!foundAnother)
    m_elements.reset(bitToRemove);

  m_atomicNumbers.swapAndPop(index);
  m_graph.removeVertex(index);

  ensureLayerInfo().layer.removeAtom(index);

  return true;
}

bool Molecule::removeAtom(const AtomType& atom_)
{
  return removeAtom(atom_.index());
}

void Molecule::clearAtoms()
{
  // Atom-indexed members -- see the comment above the helpers in the
  // anonymous namespace at the top of this file. Keep this list parallel
  // with swapAtom() and removeAtom().
  m_positions2d.clear();
  m_positions3d.clear();
  m_atomLabels.clear();
  m_hybridizations.clear();
  m_formalCharges.clear();
  m_isotopes.clear();
  m_forceVectors.clear();
  m_colors.clear();
  m_selectedAtoms.clear();
  m_coordinates3d.clear();
  m_frozenAtomMask.resize(0);

  // With no atoms left there is nothing for any calculated result to be about,
  // nor for a scan coordinate to name.
  clearCalculatedResults();
  m_constraints.clear();
  setScanCoordinates({});

  m_atomicNumbers.clear();
  m_bondOrders.clear();
  m_bondLabels.clear();
  m_residueLabels.clear();
  m_graph.clear();
  m_atomProperties.clear();
  m_bondProperties.clear();
  m_residues.clear();
  m_residueProperties.clear();
  m_conformerProperties.clear();
  m_timesteps.clear();
  ensureLayerInfo().layer.clear();
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
  // See bond(): a released build has no assert, so refuse the bond rather
  // than corrupting the graph.
  if (atom1 >= m_atomicNumbers.size() || atom2 >= m_atomicNumbers.size())
    return BondType();
  Index index = bond(atom1, atom2).index();
  if (index >= bondCount()) {
    m_graph.addEdge(atom1, atom2);
    m_bondOrders.push_back(order);
    m_bondProperties.addEntry();
    index = static_cast<Index>(m_graph.edgeCount() - 1);
  } else {
    m_bondOrders[index] = order;
  }
  // Any existing charges are invalidated, but deliberately *not*
  // clearCalculatedResults(): perceiveBondsSimple() adds bonds one at a time,
  // and the player tool re-perceives connectivity on every animation frame
  // when dynamic bonding is on (see clearBonds()).
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

void Molecule::clearCalculatedResults()
{
  m_partialCharges.clear();
  m_forceVectors.clear();
  // Not m_velocities.clear(): the mean speeds and temperatures derived from
  // them are properties of their own, and have to go at the same time.
  clearVelocities();
  m_vibrations.clear();
  m_spectra.clear();
}

bool Molecule::removeBond(Index index)
{
  if (index >= bondCount())
    return false;
  m_bondProperties.removeEntry(index, bondCount());
  // Bond-indexed like m_bondOrders below, so it has to run before
  // m_graph.removeEdge() changes bondCount().
  removeBondEntry(m_bondLabels, index, bondCount());
  m_graph.removeEdge(index);
  m_bondOrders.swapAndPop(index);
  // Connectivity is part of what was calculated from, so a bond going away
  // invalidates the results just as an atom going away does.
  clearCalculatedResults();
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
  m_bondProperties.clear();
  m_bondLabels.clear();
  m_graph.removeEdges();
  m_graph.setSize(atomCount());

  // Deliberately *not* clearCalculatedResults(), unlike removeBond(). This is
  // used as "re-perceive connectivity" rather than as a structural edit: the
  // player tool calls it with perceiveBondsSimple() on every animation frame
  // when dynamic bonding is on, so dropping the vibrations here would destroy
  // the normal modes being animated. Partial charges are cleared because they
  // depend directly on bond orders and are cheap to recompute.
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
  // Not assert(): NDEBUG removes it, and an out-of-range index from a file
  // reader then indexes the graph's edge map out of bounds instead.
  if (atomId1 >= atomCount() || atomId2 >= atomCount())
    return BondType();

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
  m_activeCubeIndex = 0;
}

bool Molecule::setActiveCubeIndex(Index index)
{
  if (index < static_cast<Index>(m_cubes.size())) {
    m_activeCubeIndex = index;
    return true;
  }
  return false;
}

Cube* Molecule::activeCube()
{
  if (m_activeCubeIndex < static_cast<Index>(m_cubes.size()))
    return m_cubes[m_activeCubeIndex];
  else if (!m_cubes.empty())
    return m_cubes[0];
  return nullptr;
}

const Cube* Molecule::activeCube() const
{
  if (m_activeCubeIndex < static_cast<Index>(m_cubes.size()))
    return m_cubes[m_activeCubeIndex];
  else if (!m_cubes.empty())
    return m_cubes[0];
  return nullptr;
}

std::string Molecule::formula(const std::string& delimiter, int over) const
{
  // A map of element symbols (including isotopes) to their quantity.
  std::map<std::string, size_t> componentsCount = formulaComposition();

  std::stringstream result;
  std::map<std::string, size_t>::iterator iter;

  // Carbons first
  iter = componentsCount.find("C");
  if (iter != componentsCount.end()) {
    result << "C";
    if (iter->second > static_cast<size_t>(over))
      result << delimiter << iter->second;
    componentsCount.erase(iter);

    // If carbon is present, hydrogens are next (including D and T).
    iter = componentsCount.find("H");
    if (iter != componentsCount.end()) {
      result << delimiter << "H";
      if (iter->second > static_cast<size_t>(over))
        result << delimiter << iter->second;
      componentsCount.erase(iter);
    }
    iter = componentsCount.find("D");
    if (iter != componentsCount.end()) {
      result << delimiter << "D";
      if (iter->second > static_cast<size_t>(over))
        result << delimiter << iter->second;
      componentsCount.erase(iter);
    }
    iter = componentsCount.find("T");
    if (iter != componentsCount.end()) {
      result << delimiter << "T";
      if (iter->second > static_cast<size_t>(over))
        result << delimiter << iter->second;
      componentsCount.erase(iter);
    }
  }

  // The rest (alphabetically, since std::map<std::string> sorts by key):
  iter = componentsCount.begin();
  while (iter != componentsCount.end()) {
    result << delimiter << iter->first;
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
  for (Index i = 0; i < atomCount(); ++i) {
    if (isotope(i) > 0)
      m += Elements::isotopeMass(m_atomicNumbers[i], isotope(i));
    else
      m += Elements::mass(m_atomicNumbers[i]);
  }
  return m;
}

double Molecule::monoisotopicMass() const
{
  double m(0.0);
  for (Index i = 0; i < atomCount(); ++i)
    // default will be the most common isotope
    m += Elements::isotopeMass(m_atomicNumbers[i], isotope(i));
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
  Real totalMass = 0.0;
  for (Index i = 0; i < atomCount(); ++i) {
    AtomType curr_atom = atom(i);
    auto mass = Elements::mass(m_atomicNumbers[i]);
    if (isotope(i) > 0)
      mass = Elements::isotopeMass(m_atomicNumbers[i], isotope(i));

    center += (curr_atom.position3d() * mass);
    totalMass += mass;
  }
  center /= totalMass;
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
  Eigen::JacobiSVD<MatrixX> svd(coord,
                                Eigen::ComputeThinU | Eigen::ComputeThinV);
  Vector3 plane_normal = svd.matrixU().rightCols<1>();

  return std::make_pair(centroid, plane_normal);
}

namespace {

// The active conformer index as a map key. m_coordinate3dIndex is only
// negative if something has set it out of range; treat that as conformer 0
// rather than wrapping to a huge key.
size_t vibrationKey(int coordinateIndex)
{
  return coordinateIndex > 0 ? static_cast<size_t>(coordinateIndex) : 0;
}

} // namespace

Array<double> Molecule::vibrationFrequencies() const
{
  return vibrationFrequencies(vibrationKey(m_coordinate3dIndex));
}

void Molecule::setVibrationFrequencies(const Array<double>& freq)
{
  setVibrationFrequencies(freq, vibrationKey(m_coordinate3dIndex));
}

Array<double> Molecule::vibrationIRIntensities() const
{
  return vibrationIRIntensities(vibrationKey(m_coordinate3dIndex));
}

void Molecule::setVibrationIRIntensities(const Array<double>& intensities)
{
  setVibrationIRIntensities(intensities, vibrationKey(m_coordinate3dIndex));
}

Array<double> Molecule::vibrationRamanIntensities() const
{
  return vibrationRamanIntensities(vibrationKey(m_coordinate3dIndex));
}

void Molecule::setVibrationRamanIntensities(const Array<double>& intensities)
{
  setVibrationRamanIntensities(intensities, vibrationKey(m_coordinate3dIndex));
}

Array<Vector3> Molecule::vibrationLx(int mode) const
{
  return vibrationLx(mode, vibrationKey(m_coordinate3dIndex));
}

void Molecule::setVibrationLx(const Array<Array<Vector3>>& lx)
{
  setVibrationLx(lx, vibrationKey(m_coordinate3dIndex));
}

const Molecule::VibrationData* Molecule::vibrationData(
  size_t conformerIndex) const
{
  auto match = m_vibrations.find(conformerIndex);
  return match == m_vibrations.end() ? nullptr : &match->second;
}

void Molecule::setVibrationData(const VibrationData& data,
                                size_t conformerIndex)
{
  m_vibrations[conformerIndex] = data;
}

Array<double> Molecule::vibrationFrequencies(size_t conformerIndex) const
{
  const VibrationData* data = vibrationData(conformerIndex);
  return data ? data->frequencies : Array<double>();
}

void Molecule::setVibrationFrequencies(const Array<double>& freq,
                                       size_t conformerIndex)
{
  m_vibrations[conformerIndex].frequencies = freq;
}

Array<double> Molecule::vibrationIRIntensities(size_t conformerIndex) const
{
  const VibrationData* data = vibrationData(conformerIndex);
  return data ? data->irIntensities : Array<double>();
}

void Molecule::setVibrationIRIntensities(const Array<double>& intensities,
                                         size_t conformerIndex)
{
  m_vibrations[conformerIndex].irIntensities = intensities;
}

Array<double> Molecule::vibrationRamanIntensities(size_t conformerIndex) const
{
  const VibrationData* data = vibrationData(conformerIndex);
  return data ? data->ramanIntensities : Array<double>();
}

void Molecule::setVibrationRamanIntensities(const Array<double>& intensities,
                                            size_t conformerIndex)
{
  m_vibrations[conformerIndex].ramanIntensities = intensities;
}

Array<Vector3> Molecule::vibrationLx(int mode, size_t conformerIndex) const
{
  const VibrationData* data = vibrationData(conformerIndex);
  if (data == nullptr || mode < 0 || mode >= static_cast<int>(data->lx.size()))
    return Array<Vector3>();
  return data->lx[mode];
}

void Molecule::setVibrationLx(const Array<Array<Vector3>>& lx,
                              size_t conformerIndex)
{
  m_vibrations[conformerIndex].lx = lx;
}

bool Molecule::hasVibrations(size_t conformerIndex) const
{
  const VibrationData* data = vibrationData(conformerIndex);
  return data != nullptr && !data->isEmpty();
}

bool Molecule::hasVibrations() const
{
  return hasVibrations(vibrationKey(m_coordinate3dIndex));
}

size_t Molecule::vibrationConformerCount() const
{
  return vibrationConformers().size();
}

Array<size_t> Molecule::vibrationConformers() const
{
  Array<size_t> indices;
  // std::map iterates in increasing key order.
  for (const auto& entry : m_vibrations) {
    if (!entry.second.isEmpty())
      indices.push_back(entry.first);
  }
  return indices;
}

void Molecule::clearVibrations()
{
  m_vibrations.clear();
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
    const unsigned int target =
      atomValence(atomicNumber(i), formalCharge(i), bonds(i).size());

    // check to see if the atom needs valence
    //  if boSum is too large, then the atom already has too many bonds
    //  so return zero instead of an underflow
    unsaturatedValence[i] =
      target > boSum ? static_cast<unsigned char>(target - boSum) : 0;

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
    m_coordinate3dIndex = coord;
    return true;
  }
  return false;
}

int Molecule::coordinate3d() const
{
  return m_coordinate3dIndex;
}

void Molecule::clearCoordinate3d()
{
  // Flattening the trajectory keeps the geometry that is on screen, so keep
  // the vibrations that go with it and drop the rest. The surviving set moves
  // to key 0 to stay with the active index, which is reset below.
  std::map<size_t, VibrationData> kept;
  auto active = m_vibrations.find(vibrationKey(m_coordinate3dIndex));
  if (active != m_vibrations.end())
    kept[0] = std::move(active->second);
  m_vibrations.swap(kept);

  m_coordinates3d.clear();
  m_conformerProperties.clear();
  m_coordinate3dIndex = 0;
}

Array<Vector3> Molecule::coordinate3d(size_t index) const
{
  return m_coordinates3d[index];
}

const Array<Vector3>& Molecule::coordinate3dRef(size_t index) const
{
  static const Array<Vector3> empty;
  if (index >= m_coordinates3d.size())
    return empty;

  return m_coordinates3d[index];
}

bool Molecule::setCoordinate3d(const Array<Vector3>& coords, size_t index)
{
  if (m_coordinates3d.size() <= index)
    m_coordinates3d.resize(index + 1);
  m_coordinates3d[index] = coords;
  return true;
}

namespace {

// Boltzmann's constant in the units the velocities here are expressed in:
// 1.380649e-23 J/K over 1 amu A^2/ps^2, which is 1.66053906660e-23 J. It is
// the gas constant in kJ/(mol K) under another name, since one amu A^2/ps^2
// is exactly 0.01 kJ/mol.
constexpr double BoltzmannAmuAngstrom2PerPs2PerKelvin = 0.831446261815324;

// Mean and population standard deviation of the atomic speeds in @p velocities.
std::pair<double, double> speedStatistics(const Array<Vector3>& velocities)
{
  if (velocities.empty())
    return { 0.0, 0.0 };

  double sum = 0.0;
  for (const auto& velocity : velocities)
    sum += velocity.norm();
  const double mean = sum / velocities.size();

  double variance = 0.0;
  for (const auto& velocity : velocities) {
    const double deviation = velocity.norm() - mean;
    variance += deviation * deviation;
  }

  return { mean, std::sqrt(variance / velocities.size()) };
}

} // namespace

void Molecule::estimateVelocities()
{
  // A timestep for every coordinate set is all this needs; a file that
  // recorded more of them than it has geometries still says when each
  // geometry was written.
  if (m_timesteps.size() < m_coordinates3d.size())
    return;

  // Timesteps need not be evenly spaced -- a trajectory written every n steps
  // of a variable-timestep integrator is not -- so each set gets its own
  // interval. The first has nothing before it, and borrows the second's.
  std::vector<double> intervals(m_coordinates3d.size(), 0.0);
  for (size_t i = 1; i < intervals.size(); ++i)
    intervals[i] = m_timesteps[i] - m_timesteps[i - 1];
  if (intervals.size() > 1)
    intervals[0] = intervals[1];

  estimateVelocities(intervals);
}

void Molecule::estimateVelocities(double timeStep)
{
  estimateVelocities(std::vector<double>(m_coordinates3d.size(), timeStep));
}

void Molecule::estimateVelocities(const std::vector<double>& intervals)
{
  m_velocities.clear();

  // One coordinate set is a geometry, not a trajectory: there is nothing to
  // difference, and the derived properties below end up cleared rather than
  // left stale.
  const size_t sets = std::min(m_coordinates3d.size(), intervals.size());
  if (sets >= 2) {
    m_velocities.resize(sets);

    for (size_t i = 0; i < sets; ++i) {
      const double dt = intervals[i];
      // A repeated timestep says nothing about how fast the atoms moved, so
      // that set keeps its zero velocities rather than a division by zero.
      if (std::abs(dt) < 1e-12)
        continue;

      // Backward difference everywhere but the first set, which has nothing
      // before it and so takes a forward difference instead.
      const Array<Vector3>& later =
        (i > 0) ? m_coordinates3d[i] : m_coordinates3d[1];
      const Array<Vector3>& earlier =
        (i > 0) ? m_coordinates3d[i - 1] : m_coordinates3d[0];

      // The sets should all describe the same atoms, but a malformed
      // trajectory can hold a short one -- go only as far as both of them do.
      const size_t count =
        std::min(atomCount(), std::min(later.size(), earlier.size()));

      m_velocities[i].resize(count);
      for (size_t j = 0; j < count; ++j)
        m_velocities[i][j] = (later[j] - earlier[j]) / dt;
    }
  }

  updateVelocityProperties();
}

void Molecule::updateVelocityProperties()
{
  std::vector<double> speeds(m_velocities.size(), 0.0);
  std::vector<double> deviations(m_velocities.size(), 0.0);
  std::vector<double> temperatures(m_velocities.size(), 0.0);

  for (size_t i = 0; i < m_velocities.size(); ++i) {
    const auto [mean, deviation] = speedStatistics(m_velocities[i]);
    speeds[i] = mean;
    deviations[i] = deviation;
    temperatures[i] = temperature(m_velocities[i]);
  }

  // One scalar per coordinate set belongs with the other trajectory
  // properties -- "energies", "forces" -- so that anything able to plot one
  // of those can plot these without knowing about velocities at all.
  setData("velocities", speeds);
  setData("velocityDeviations", deviations);
  setData("temperatures", temperatures);
}

double Molecule::atomMass(Index atomId) const
{
  // A labelled atom weighs what its isotope weighs, which is the difference
  // between a C-H and a C-D stretch -- and, here, between the right
  // temperature and one several percent out. Same rule as mass().
  if (isotope(atomId) > 0)
    return Elements::isotopeMass(m_atomicNumbers[atomId], isotope(atomId));
  return Elements::mass(m_atomicNumbers[atomId]);
}

double Molecule::temperature(const Array<Vector3>& velocities) const
{
  // Three degrees of freedom go to the center-of-mass translation removed
  // below, so two atoms are the fewest that leave any motion to measure.
  const size_t count = std::min(atomCount(), velocities.size());
  if (count < 2)
    return 0.0;

  Vector3 momentum = Vector3::Zero();
  double totalMass = 0.0;
  for (size_t j = 0; j < count; ++j) {
    const double mass = atomMass(j);
    momentum += mass * velocities[j];
    totalMass += mass;
  }
  if (totalMass <= 0.0)
    return 0.0;
  const Vector3 centerOfMassVelocity = momentum / totalMass;

  // Kinetic energy in the center-of-mass frame, in amu A^2/ps^2. Drift of the
  // molecule as a whole is not thermal motion, and velocities differenced
  // from a trajectory pick it up readily, so it comes out rather than being
  // counted as heat.
  double kineticEnergy = 0.0;
  for (size_t j = 0; j < count; ++j) {
    const Vector3 thermal = velocities[j] - centerOfMassVelocity;
    kineticEnergy += atomMass(j) * thermal.squaredNorm();
  }
  kineticEnergy *= 0.5;

  // Equipartition: T = 2 KE / (N_df k_B). Bond constraints (SHAKE and the
  // like) take away further degrees of freedom, but nothing in a trajectory
  // records them, so a constrained run reads low here.
  const double degreesOfFreedom = 3.0 * count - 3.0;
  return 2.0 * kineticEnergy /
         (degreesOfFreedom * BoltzmannAmuAngstrom2PerPs2PerKelvin);
}

Array<Vector3> Molecule::velocities(int index) const
{
  if (index >= 0 && index < static_cast<int>(m_velocities.size()))
    return m_velocities[index];
  return Array<Vector3>();
}

bool Molecule::setVelocities(const Array<Vector3>& velocities, int index)
{
  if (index < 0)
    return false;

  if (static_cast<int>(m_velocities.size()) <= index)
    m_velocities.resize(index + 1);
  m_velocities[index] = velocities;
  return true;
}

void Molecule::clearVelocities()
{
  m_velocities.clear();
  updateVelocityProperties();
}

double Molecule::timeStep(int index, bool& status) const
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

const Residue& Molecule::residue(Index index) const
{
  return m_residues[index];
}

Index Molecule::residueCount() const
{
  return static_cast<Index>(m_residues.size());
}

std::string Molecule::residueLabel(Index residueId) const
{
  return residueId < m_residueLabels.size() ? m_residueLabels[residueId] : "";
}

bool Molecule::setResidueLabels(const Core::Array<std::string>& labels)
{
  if (labels.size() == residueCount() || labels.size() == 0) {
    m_residueLabels = labels;
    return true;
  }
  return false;
}

bool Molecule::setResidueLabel(Index residueId, const std::string& label)
{
  if (residueId < residueCount()) {
    if (residueId >= m_residueLabels.size())
      m_residueLabels.resize(residueCount(), "");
    m_residueLabels[residueId] = label;
    return true;
  }
  return false;
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

    // update element mask, with the same clamp for custom elements as
    // addAtom() and setAtomicNumber()
    m_elements.reset();
    for (unsigned char atomicNumber : m_atomicNumbers) {
      if (atomicNumber < element_count)
        m_elements.set(atomicNumber);
      else
        m_elements.set(element_count - 1);
    }
    // update colors too
    if (nums.size() == m_colors.size()) {
      for (Index i = 0; i < nums.size(); ++i)
        m_colors[i] = Vector3ub(Elements::color(m_atomicNumbers[i]));
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
    for (unsigned char atomicNumber : m_atomicNumbers) {
      // The same clamp addAtom() applies. Custom elements are numbered at or
      // above element_count, and std::bitset::set() throws for those, so
      // without this a molecule holding one cannot be edited at all.
      if (atomicNumber < element_count)
        m_elements.set(atomicNumber);
      else
        m_elements.set(element_count - 1);
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
  const double tolerance = 1.0e-3;

  // A map of atomic numbers to their quantity (using double for fractional
  // contributions when there's a unit cell)
  std::map<unsigned char, double> compositionDouble;

  // Check if we have a unit cell - if so, we need to account for fractional
  // atoms at corners, edges, and faces
  if (m_unitCell != nullptr) {
    for (Index i = 0; i < atomCount(); ++i) {
      unsigned char atomicNum = m_atomicNumbers[i];
      Vector3 fracCoords = m_unitCell->toFractional(m_positions3d[i]);

      // Count how many coordinates are at boundaries (0 or 1)
      int boundaryCount = 0;
      for (int j = 0; j < 3; ++j) {
        double coord = fracCoords[j];
        // Check if close to 0 or 1
        if (std::fabs(coord) < tolerance ||
            std::fabs(coord - 1.0) < tolerance) {
          ++boundaryCount;
        }
      }

      // Calculate fractional contribution based on boundary count
      // Corner atoms (3 boundaries): 1/8
      // Edge atoms (2 boundaries): 1/4
      // Face atoms (1 boundary): 1/2
      // Interior atoms (0 boundaries): 1
      double weight = 1.0;
      if (boundaryCount == 3) {
        weight = 1.0 / 8.0;
      } else if (boundaryCount == 2) {
        weight = 1.0 / 4.0;
      } else if (boundaryCount == 1) {
        weight = 1.0 / 2.0;
      }

      compositionDouble[atomicNum] += weight;
    }
  } else {
    // No unit cell, just count atoms normally
    for (unsigned char atomicNum : m_atomicNumbers) {
      compositionDouble[atomicNum] += 1.0;
    }
  }

  // Convert to size_t by rounding to nearest integer
  std::map<unsigned char, size_t> composition;
  for (const auto& pair : compositionDouble) {
    size_t roundedCount = static_cast<size_t>(std::round(pair.second));
    if (roundedCount > 0) {
      composition[pair.first] = roundedCount;
    }
  }

  return composition;
}

std::map<std::string, size_t> Molecule::formulaComposition() const
{
  const double tolerance = 1.0e-3;

  // A map of element symbols (with isotopes) to their quantity
  // Using double to accumulate fractional contributions from unit cells
  std::map<std::string, double> compositionDouble;

  for (Index i = 0; i < atomCount(); ++i) {
    unsigned char atomicNum = m_atomicNumbers[i];
    std::string atomSymbol(Elements::symbol(atomicNum));

    // Handle isotopes
    unsigned short iso = isotope(i);
    if (iso > 0) {
      if (atomicNum == 1 && iso == 1)
        atomSymbol = "H";
      else if (atomicNum == 1 && iso == 2)
        atomSymbol = "D";
      else if (atomicNum == 1 && iso == 3)
        atomSymbol = "T";
      else
        // e.g., 13C
        atomSymbol = std::to_string(iso) + atomSymbol;
    }

    // Calculate fractional contribution for unit cells
    double weight = 1.0;
    if (m_unitCell != nullptr) {
      Vector3 fracCoords = m_unitCell->toFractional(m_positions3d[i]);

      // Count how many coordinates are at boundaries (0 or 1)
      int boundaryCount = 0;
      for (int j = 0; j < 3; ++j) {
        double coord = fracCoords[j];
        if (std::fabs(coord) < tolerance ||
            std::fabs(coord - 1.0) < tolerance) {
          ++boundaryCount;
        }
      }

      // Corner atoms (3 boundaries): 1/8
      // Edge atoms (2 boundaries): 1/4
      // Face atoms (1 boundary): 1/2
      if (boundaryCount == 3) {
        weight = 1.0 / 8.0;
      } else if (boundaryCount == 2) {
        weight = 1.0 / 4.0;
      } else if (boundaryCount == 1) {
        weight = 1.0 / 2.0;
      }
    }

    compositionDouble[atomSymbol] += weight;
  }

  // Convert to size_t by rounding to nearest integer
  std::map<std::string, size_t> composition;
  for (const auto& pair : compositionDouble) {
    size_t roundedCount = static_cast<size_t>(std::round(pair.second));
    if (roundedCount > 0) {
      composition[pair.first] = roundedCount;
    }
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
    // removeBond() returns false without removing anything when the index is
    // past bondCount(), which means the graph's edge list and the bond arrays
    // disagree. Ignoring that spun here forever: the edge list never shrinks,
    // so the loop never reaches its only exit. Stop instead, and say that not
    // every bond could be removed.
    if (!removeBond(bond))
      return false;
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
    if (ensureLayerInfo().layer.getLayerID(i - 1) == layer) {
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
    if (noSelection || atomSelected(i)) {

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
