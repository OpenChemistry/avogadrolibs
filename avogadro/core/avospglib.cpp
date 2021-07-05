/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "avospglib.h"

#include "array.h"
#include "matrix.h"
#include "molecule.h"
#include "unitcell.h"
#include "vector.h"

#include <iostream>

extern "C" {
#include "spglib.h"
}

namespace Avogadro {
namespace Core {

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
  double(*positions)[3] = new double[numAtoms][3];
  int* types = new int[numAtoms];

  const Array<unsigned char>& atomicNums = mol.atomicNumbers();
  const Array<Vector3>& pos = mol.atomPositions3d();

  // Positions need to be in fractional coordinates
  for (Index i = 0; i < numAtoms; ++i) {
    Vector3 fracCoords = uc->toFractional(pos[i]);
    positions[i][0] = fracCoords[0];
    positions[i][1] = fracCoords[1];
    positions[i][2] = fracCoords[2];
    types[i] = atomicNums[i];
  }

  SpglibDataset* data =
    spg_get_dataset(lattice, positions, types, numAtoms, cartTol);

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
  // spg_standardize_cell() can cause the number of atoms to increase by
  // as much as 4x if toPrimitive is false.
  // So, we must make these arrays at least 4x the number of atoms.
  // If toPrimitive is true, then we will just use the number of atoms.
  // See http://atztogo.github.io/spglib/api.html#spg-standardize-cell
  int numAtomsMultiplier = toPrimitive ? 1 : 4;
  double(*positions)[3] = new double[numAtoms * numAtomsMultiplier][3];
  int* types = new int[numAtoms * numAtomsMultiplier];

  const Array<unsigned char>& atomicNums = mol.atomicNumbers();
  const Array<Vector3>& pos = mol.atomPositions3d();

  // Positions need to be in fractional coordinates
  for (Index i = 0; i < numAtoms; ++i) {
    Vector3 fracCoords = uc->toFractional(pos[i]);
    positions[i][0] = fracCoords[0];
    positions[i][1] = fracCoords[1];
    positions[i][2] = fracCoords[2];
    types[i] = atomicNums[i];
  }

  // Run the spglib algorithm
  Index newNumAtoms = spg_standardize_cell(lattice, positions, types, numAtoms,
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

  UnitCell* newCell = new UnitCell(newCellMat);
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

} // end Core namespace
} // end Avogadro namespace
