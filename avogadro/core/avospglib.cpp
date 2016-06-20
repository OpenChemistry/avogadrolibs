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
#include "spglib/spglib.h"
}

namespace Avogadro {
namespace Core {

unsigned short AvoSpglib::getHallNumber(const Molecule &mol, double cartTol)
{
  if (!mol.unitCell())
    return 0;

  const UnitCell *uc = mol.unitCell();
  Matrix3 cellMat = uc->cellMatrix();

  double lattice[3][3];
  // Spglib expects column vectors
  for (Index i = 0; i < 3; ++i) {
    for (Index j = 0; j < 3; ++j) {
      lattice[i][j] = cellMat(i,j);
    }
  }

  Index numAtoms = mol.atomCount();
  double (*positions)[3] = new double[numAtoms][3];
  int *types = new int[numAtoms];

  const Array<unsigned char> &atomicNums = mol.atomicNumbers();
  const Array<Vector3> &pos = mol.atomPositions3d();

  // Positions need to be in fractional coordinates
  for (Index i = 0; i < numAtoms; ++i) {
    Vector3 fracCoords = uc->toFractional(pos[i]);
    positions[i][0] = fracCoords[0];
    positions[i][1] = fracCoords[1];
    positions[i][2] = fracCoords[2];
    types[i] = atomicNums[i];
  }

  SpglibDataset *data = spg_get_dataset(lattice, positions, types,
                                        numAtoms, cartTol);

  if (!data) {
    std::cerr << "Cannot determine spacegroup.\n";
    delete [] positions;
    delete [] types;
    return 0;
  }

  unsigned short hallNumber = data->hall_number;

  // Cleanup time
  spg_free_dataset(data);
  delete [] positions;
  delete [] types;

  return hallNumber;
}

} // end Core namespace
} // end Avogadro namespace
