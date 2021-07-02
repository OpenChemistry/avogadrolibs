/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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
#include <iostream>

namespace Avogadro {
namespace Core {

Molecule::Molecule() : m_basisSet(nullptr), m_unitCell(nullptr) {}

Molecule::Molecule(const Molecule& other)
  : m_data(other.m_data), m_customElementMap(other.m_customElementMap),
    m_positions2d(other.m_positions2d), m_positions3d(other.m_positions3d),
    m_coordinates3d(other.m_coordinates3d), m_timesteps(other.m_timesteps),
    m_hybridizations(other.m_hybridizations),
    m_formalCharges(other.m_formalCharges), m_colors(other.m_colors),
    m_vibrationFrequencies(other.m_vibrationFrequencies),
    m_vibrationIntensities(other.m_vibrationIntensities),
    m_vibrationLx(other.m_vibrationLx), m_selectedAtoms(other.m_selectedAtoms),
    m_meshes(std::vector<Mesh*>()), m_cubes(std::vector<Cube*>()),
    m_basisSet(other.m_basisSet ? other.m_basisSet->clone() : nullptr),
    m_unitCell(other.m_unitCell ? new UnitCell(*other.m_unitCell) : nullptr),
    m_residues(other.m_residues), MoleculeGraph(other)
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
    m_residues(std::move(other.m_residues)), MoleculeGraph(other)
{
  m_basisSet = other.m_basisSet;
  other.m_basisSet = nullptr;

  m_unitCell = other.m_unitCell;
  other.m_unitCell = nullptr;
}

Molecule& Molecule::operator=(const Molecule& other)
{
  MoleculeGraph::operator=(other);
  if (this != &other) {
    m_data = other.m_data;
    m_customElementMap = other.m_customElementMap;
    m_positions2d = other.m_positions2d;
    m_positions3d = other.m_positions3d;
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
  MoleculeGraph::operator=(other);
  if (this != &other) {
    m_data = std::move(other.m_data);
    m_customElementMap = std::move(other.m_customElementMap);
    m_positions2d = std::move(other.m_positions2d);
    m_positions3d = std::move(other.m_positions3d);
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
  // Add the atomic number.
  MoleculeGraph::addAtom(number);
  return AtomType(this, static_cast<Index>(atomCount() - 1));
}
bool Molecule::removeAtom(Index index)
{
  if (index >= atomCount())
    return false;
  Index newSize = static_cast<Index>(atomCount() - 1);
  m_positions2d.swapAndPop(index);
  m_positions3d.swapAndPop(index);
  m_hybridizations.swapAndPop(index);
  m_formalCharges.swapAndPop(index);
  m_colors.swapAndPop(index);
  Core::MoleculeGraph::removeAtom(index);
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
  m_hybridizations.clear();
  m_formalCharges.clear();
  m_colors.clear();
  Core::MoleculeGraph::clearAtoms();
}

Molecule::AtomType Molecule::atom(Index index) const
{
  assert(index < atomCount());
  return AtomType(const_cast<Molecule*>(this), index);
}

Molecule::BondType Molecule::addBond(Index atom1, Index atom2,
                                     unsigned char order)
{
  if (Core::MoleculeGraph::addBond(atom1, atom2, order)) {
    return BondType(this, bondCount() - 1);
  }
  return BondType();
}

Molecule::BondType Molecule::addBond(const AtomType& a, const AtomType& b,
                                     unsigned char order)
{
  assert(a.isValid() && a.molecule() == this);
  assert(b.isValid() && b.molecule() == this);

  return addBond(a.index(), b.index(), order);
}

bool Molecule::removeBond(Index index)
{
  return Core::MoleculeGraph::removeBond(index);
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
  Core::MoleculeGraph::clearBonds();
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
  Index index = findBond(atomId1, atomId2);
  if (index == bondCount())
    return BondType();
  return BondType(const_cast<Molecule*>(this), index);
}

Array<Molecule::BondType> Molecule::bonds(const AtomType& a)
{
  if (!a.isValid())
    return Array<BondType>();

  return bonds(a.index());
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

} // namespace Core
} // namespace Avogadro
