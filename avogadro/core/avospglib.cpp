/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "avospglib.h"

#include "array.h"
#include "matrix.h"
#include "molecule.h"
#include "unitcell.h"
#include "vector.h"

#include <array>
#include <iostream>
#include <vector>

extern "C"
{
#include "spglib.h"
}

namespace Avogadro::Core {

unsigned short AvoSpglib::getHallNumber(Molecule& mol, double cartTol)
{
  if (!mol.unitCell())
    return 0;

  const UnitCell* uc = mol.unitCell();
  Matrix3 cellMat = uc->cellMatrix();

  double lattice[3][3];
  // Spglib expects column vectors
  for (Index i = 0; i < 3; ++i) {
    for (Index j = 0; j < 3; ++j) {
      lattice[i][j] = cellMat(i, j);
    }
  }

  Index numAtoms = mol.atomCount();
  const Array<unsigned char>& atomicNums = mol.atomicNumbers();
  const Array<Vector3>& pos = mol.atomPositions3d();

  // Use vectors to filter out translational duplicates
  std::vector<std::array<double, 3>> positionsVec;
  std::vector<int> typesVec;
  positionsVec.reserve(numAtoms);
  typesVec.reserve(numAtoms);

  // Positions need to be in fractional coordinates
  for (Index i = 0; i < numAtoms; ++i) {
    Vector3 fracCoords = uc->toFractional(pos[i]);
    // Skip atoms with any fractional coordinate ~1.0
    // (translational duplicates of other atoms ~0.0
    if (std::abs(fracCoords[0] - 1.0) < 1e-8 ||
        std::abs(fracCoords[1] - 1.0) < 1e-8 ||
        std::abs(fracCoords[2] - 1.0) < 1e-8)
      continue;
    positionsVec.push_back({ fracCoords[0], fracCoords[1], fracCoords[2] });
    typesVec.push_back(atomicNums[i]);
  }

  Index filteredNumAtoms = positionsVec.size();
  if (filteredNumAtoms == 0) {
    std::cerr << "No valid atoms found for spacegroup determination.\n";
    return 0;
  }

  // Convert to C-style arrays for spglib
  auto* positions = new double[filteredNumAtoms][3];
  int* types = new int[filteredNumAtoms];
  for (Index i = 0; i < filteredNumAtoms; ++i) {
    positions[i][0] = positionsVec[i][0];
    positions[i][1] = positionsVec[i][1];
    positions[i][2] = positionsVec[i][2];
    types[i] = typesVec[i];
  }

  SpglibDataset* data =
    spg_get_dataset(lattice, positions, types, filteredNumAtoms, cartTol);

  if (!data) {
    std::cerr << "Cannot determine spacegroup.\n";
    delete[] positions;
    delete[] types;
    return 0;
  }

  unsigned short hallNumber = data->hall_number;

  // Cleanup time
  spg_free_dataset(data);
  delete[] positions;
  delete[] types;

  mol.setHallNumber(hallNumber);
  return hallNumber;
}

bool AvoSpglib::reduceToPrimitive(Molecule& mol, double cartTol)
{
  return standardizeCell(mol, cartTol, true, false);
}

bool AvoSpglib::conventionalizeCell(Molecule& mol, double cartTol)
{
  return standardizeCell(mol, cartTol, false, true);
}

bool AvoSpglib::symmetrize(Molecule& mol, double cartTol)
{
  return standardizeCell(mol, cartTol, true, true);
}

bool AvoSpglib::standardizeCell(Molecule& mol, double cartTol, bool toPrimitive,
                                bool idealize)
{
  if (!mol.unitCell())
    return false;

  const UnitCell* uc = mol.unitCell();
  Matrix3 cellMat = uc->cellMatrix();

  double lattice[3][3];
  // Spglib expects column vectors
  for (Index i = 0; i < 3; ++i) {
    for (Index j = 0; j < 3; ++j) {
      lattice[i][j] = cellMat(i, j);
    }
  }

  Index numAtoms = mol.atomCount();
  const Array<unsigned char>& atomicNums = mol.atomicNumbers();
  const Array<Vector3>& pos = mol.atomPositions3d();

  // Use vectors to filter out translational duplicates
  // (atoms at fracCoord ~1.0)
  std::vector<std::array<double, 3>> positionsVec;
  std::vector<int> typesVec;
  positionsVec.reserve(numAtoms);
  typesVec.reserve(numAtoms);

  // Positions need to be in fractional coordinates
  for (Index i = 0; i < numAtoms; ++i) {
    Vector3 fracCoords = uc->toFractional(pos[i]);
    // Skip atoms with any fractional coordinate ~1.0
    // (translational duplicates of other atoms ~0.0
    if (std::abs(fracCoords[0] - 1.0) < 1e-8 ||
        std::abs(fracCoords[1] - 1.0) < 1e-8 ||
        std::abs(fracCoords[2] - 1.0) < 1e-8)
      continue;
    positionsVec.push_back({ fracCoords[0], fracCoords[1], fracCoords[2] });
    typesVec.push_back(atomicNums[i]);
  }

  Index filteredNumAtoms = positionsVec.size();
  if (filteredNumAtoms == 0)
    return false;

  // spg_standardize_cell() can cause the number of atoms to increase by
  // as much as 4x if toPrimitive is false.
  // So, we must make these arrays at least 4x the number of atoms.
  // If toPrimitive is true, then we will just use the number of atoms.
  // See http://atztogo.github.io/spglib/api.html#spg-standardize-cell
  int numAtomsMultiplier = toPrimitive ? 1 : 4;
  auto* positions = new double[filteredNumAtoms * numAtomsMultiplier][3];
  int* types = new int[filteredNumAtoms * numAtomsMultiplier];

  // Copy filtered data to C-style arrays for spglib
  for (Index i = 0; i < filteredNumAtoms; ++i) {
    positions[i][0] = positionsVec[i][0];
    positions[i][1] = positionsVec[i][1];
    positions[i][2] = positionsVec[i][2];
    types[i] = typesVec[i];
  }

  // Run the spglib algorithm
  Index newNumAtoms =
    spg_standardize_cell(lattice, positions, types, filteredNumAtoms,
                         toPrimitive, !idealize, cartTol);

  // If 0 is returned, the algorithm failed.
  if (newNumAtoms == 0) {
    delete[] positions;
    delete[] types;
    return false;
  }

  // Let's create a new molecule with the information
  Molecule newMol;

  // First, we will make the unit cell
  Matrix3 newCellMat;
  for (Index i = 0; i < 3; ++i) {
    for (Index j = 0; j < 3; ++j) {
      newCellMat(i, j) = lattice[i][j];
    }
  }

  auto* newCell = new UnitCell(newCellMat);
  newMol.setUnitCell(newCell);

  // Next, add in the atoms
  for (Index i = 0; i < newNumAtoms; ++i) {
    Atom newAtom = newMol.addAtom(types[i]);
    Vector3 newAtomPos(positions[i][0], positions[i][1], positions[i][2]);
    // We must convert it back to cartesian before adding it
    newAtom.setPosition3d(newCell->toCartesian(newAtomPos));
  }

  delete[] positions;
  delete[] types;

  // Set the new molecule
  mol = newMol;

  // Set the space group in the molecule
  getHallNumber(mol, cartTol);
  return true;
}

} // namespace Avogadro::Core
