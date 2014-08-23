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

  AvoSpglib::AvoSpglib(Molecule *mol) : m_molecule(mol)
  {
    if (m_molecule)
      m_unitcell = dynamic_cast<UnitCell *>(m_molecule->unitCell());

    //generate the data that will be given to Spglib
    //Is it correct to make new copies of this data?
    cellMatrix = m_unitcell->cellMatrix();
    atomicNums = m_molecule->atomicNumbers();
    size_t numAtoms = m_molecule->atomCount();
    for (size_t i = 0; i < numAtoms; ++i) {
      Atom atom = m_molecule->atom(i);
      fcoords.push_back(m_unitcell->toFractional(atom.position3d()));
    }


  }

  unsigned int AvoSpglib::getSpacegroup(const double cartTol)
  {
    // Spglib expects column vecs, so fill with transpose
    double lattice[3][3] = {
      {cellMatrix(0,0), cellMatrix(1,0), cellMatrix(2,0)},
      {cellMatrix(0,1), cellMatrix(1,1), cellMatrix(2,1)},
      {cellMatrix(0,2), cellMatrix(1,2), cellMatrix(2,2)}
    };

      // Build position and type list
    size_t numAtoms = m_molecule->atomCount();
    double (*positions)[3] = new double[numAtoms][3];
    int *types = new int[numAtoms];
    for (int i = 0; i < numAtoms; ++i) {
      types[i]          = atomicNums.at(i);
      positions[i][0]   = fcoords.at(i).x();
      positions[i][1]   = fcoords.at(i).y();
      positions[i][2]   = fcoords.at(i).z();
    }

      // find spacegroup data
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

    m_unitcell->setSpaceGroup(symb);
    m_unitcell->setSpaceGroupID(ptr->spacegroup_number);
    m_unitcell->setSpaceGroupHall(hall,ptr->hall_number);

    cout << endl;


    return ptr->hall_number;
  }

  /*unsigned int AvoSpglib::reduceToPrimitive(Array<Vector3> pos,Array<Vector3> nums,const double cartTol)
  {
    // Spglib expects column vecs, so fill with transpose
    double lattice[3][3] = {
      {cellMatrix(0,0), cellMatrix(1,0), cellMatrix(2,0)},
      {cellMatrix(0,1), cellMatrix(1,1), cellMatrix(2,1)},
      {cellMatrix(0,2), cellMatrix(1,2), cellMatrix(2,2)}
    };

      // Build position and type list
    size_t numAtoms = m_molecule->atomCount();
    double (*positions)[3] = new double[numAtoms][3];
    int *types = new int[numAtoms];
    for (int i = 0; i < numAtoms; ++i) {
      types[i]          = atomicNums.at(i);
      positions[i][0]   = fcoords.at(i).x();
      positions[i][1]   = fcoords.at(i).y();
      positions[i][2]   = fcoords.at(i).z();
    }

      // find spacegroup data
    cout << "AvoSpglib determined the Space group to be:" << endl;
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

    cout << numPrimitiveAtoms << endl;
    for (int i = 0; i < numPrimitiveAtoms; ++i) {
      nums.push_back(types[i]);
      Vector3 tmp;
      tmp.x() = positions[i][0];
      tmp.y() = positions[i][1];
      tmp.z() = positions[i][2];
      pos.push_back(tmp);
    }

    return numPrimitiveAtoms;
  }*/



}
}
