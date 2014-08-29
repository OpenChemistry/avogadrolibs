/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2014 Albert DeFusco, University of Pittsburgh

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "avospglib.h"

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>
#include <avogadro/core/array.h>

#include <iostream>
#include <math.h>

using std::cout;
using std::endl;

namespace Avogadro {
namespace Core {
  void AvoSpglib::prepareMolecule(Molecule &molecule,
                       double lattice[3][3],
                       double positions[][3],
                       int    types[])
  {
    if(!molecule.unitCell())
      return;

    UnitCell &unitcell = *molecule.unitCell();

    // Spglib expects column vecs, so fill with transpose
    Matrix3 cellMatrix = unitcell.cellMatrix();
    lattice[0][0]=cellMatrix(0,0);lattice[0][1]=cellMatrix(1,0);lattice[0][2]=cellMatrix(2,0);
    lattice[1][0]=cellMatrix(0,1);lattice[1][1]=cellMatrix(1,1);lattice[1][2]=cellMatrix(2,1);
    lattice[2][0]=cellMatrix(0,2);lattice[2][1]=cellMatrix(1,2);lattice[2][2]=cellMatrix(2,2);

    // Build position and type list
    Vector3 fcoords;
    size_t numAtoms = molecule.atomCount();
    for (size_t i = 0; i < numAtoms; ++i) {
      Atom atom = molecule.atom(i);
      fcoords=unitcell.toFractional(atom.position3d());

      types[i]          = molecule.atomicNumbers().at(i);
      positions[i][0]   = fcoords.x();
      positions[i][1]   = fcoords.y();
      positions[i][2]   = fcoords.z();
    }
  }


  void AvoSpglib::setRotations(Molecule &molecule, const int hallNumber)
  {
    if(!molecule.unitCell())
      return;

    UnitCell &unitcell = *molecule.unitCell();

    Array<Matrix3> rotate;
    Array<Vector3> shift;
    int rotations[192][3][3];
    double translations[192][3];
    int numRotations = spg_get_symmetry_from_database(rotations,translations,hallNumber);
    for (int i = 0;i<numRotations;i++)
    {
      Matrix3 m;
      m << rotations[i][0][0], rotations[i][0][1], rotations[i][0][2],
           rotations[i][1][0], rotations[i][1][1], rotations[i][1][2],
           rotations[i][2][0], rotations[i][2][1], rotations[i][2][2];
      rotate.push_back(m);

      Vector3 v;
      v << translations[i][0], translations[i][1], translations[i][2];
      shift.push_back(v);
    }
    unitcell.setTransforms(rotate,shift);
  }

  unsigned int AvoSpglib::getSpacegroup(Molecule &molecule, const double cartTol)
  {
    double lattice[3][3];
    size_t numAtoms = molecule.atomCount();
    double (*positions)[3] = new double[numAtoms][3];
    int *types = new int[numAtoms];
    prepareMolecule(molecule,lattice,positions,types);

    // determine spacegroup data
    SpglibDataset * ptr = spg_get_dataset(lattice,
                                          positions,
                                          types,
                                          numAtoms,
                                          cartTol);
    if (!ptr || ptr->spacegroup_number == 0) {
      cout << "  Cannot determine spacegroup." << endl;
        return 0;
    }

    std::string symb(ptr->international_symbol);
    std::string hall(ptr->hall_symbol);

    //set data to the unitcell
    UnitCell &unitcell = *molecule.unitCell();
    unitcell.setSpaceGroup(symb);
    unitcell.setSpaceGroupID(ptr->spacegroup_number);
    unitcell.setSpaceGroupHall(hall,ptr->hall_number);

    cout << endl;


    return ptr->hall_number;
  }

  unsigned int AvoSpglib::reduceToPrimitive(Molecule &molecule, Matrix3 &primCell, Array<Vector3> &pos,Array<unsigned char> &nums,const double cartTol)
  {
    double lattice[3][3];
    size_t numAtoms = molecule.atomCount();
    double (*positions)[3] = new double[4*numAtoms][3];
    int *types = new int[4*numAtoms];
    prepareMolecule(molecule,lattice,positions,types);

    //determine spacegroup data
    SpglibDataset * ptr = spg_get_dataset(lattice,
                                          positions,
                                          types,
                                          numAtoms,
                                          cartTol);
    if (!ptr || ptr->spacegroup_number == 0) {
      cout << "  Cannot determine spacegroup." << endl;
        return 0;
    }

    // Refine the structure
    int numBravaisAtoms =
      spg_refine_cell(lattice, positions, types,
      numAtoms, cartTol);

    // if spglib cannot refine the cell, return 0.
    if (numBravaisAtoms <= 0) {
      return 0;
    }

    // Find primitive cell. This updates lattice, positions, types
    // to primitive
    int numPrimitiveAtoms =
      spg_find_primitive(lattice, positions, types,
          numBravaisAtoms, cartTol);

    primCell <<
      lattice[0][0], lattice[0][1] , lattice[0][2],
      lattice[1][0], lattice[1][1] , lattice[1][2],
      lattice[2][0], lattice[2][1] , lattice[2][2];

    for (int i = 0; i < numPrimitiveAtoms; ++i) {
      nums.push_back(types[i]);
      Vector3 tmp;
      tmp.x() = positions[i][0];
      tmp.y() = positions[i][1];
      tmp.z() = positions[i][2];
      pos.push_back(tmp);
    }

    return numPrimitiveAtoms;
  }

  unsigned int AvoSpglib::refineCell(Molecule &molecule, Matrix3 &symmCell, Array<Vector3> &pos,Array<unsigned char> &nums,const double cartTol)
  {
    double lattice[3][3];
    size_t numAtoms = molecule.atomCount();
    double (*positions)[3] = new double[4*numAtoms][3];
    int *types = new int[4*numAtoms];
    prepareMolecule(molecule,lattice,positions,types);

    //determine spacegroup data
    SpglibDataset * ptr = spg_get_dataset(lattice,
                                          positions,
                                          types,
                                          numAtoms,
                                          cartTol);
    if (!ptr || ptr->spacegroup_number == 0) {
      cout << "  Cannot determine spacegroup." << endl;
        return 0;
    }

    // Refine the structure
    int numBravaisAtoms =
      spg_refine_cell(lattice, positions, types,
      numAtoms, cartTol);

    // if spglib cannot refine the cell, return 0.
    if (numBravaisAtoms <= 0) {
      return 0;
    }

    symmCell <<
      lattice[0][0], lattice[0][1] , lattice[0][2],
      lattice[1][0], lattice[1][1] , lattice[1][2],
      lattice[2][0], lattice[2][1] , lattice[2][2];

    for (int i = 0; i < numBravaisAtoms; ++i) {
      nums.push_back(types[i]);
      Vector3 tmp;
      tmp.x() = positions[i][0];
      tmp.y() = positions[i][1];
      tmp.z() = positions[i][2];
      pos.push_back(tmp);
    }

    return numBravaisAtoms;

  }

}
}
