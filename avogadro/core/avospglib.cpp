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

    //space group read
    cout << "The unit cell thinks this is the Space Group" << endl;
    cout << "  " << m_unitcell->getSpaceGroup() << endl;




    //generate the data that will be given to Spglib
    cellMatrix = m_unitcell->cellMatrix();
    cout << "cell matrix" << endl;
    cout << cellMatrix << endl;

    atomicNums=m_molecule->atomicNumbers();
    size_t numAtoms = m_molecule->atomCount();
    for (size_t i = 0; i < numAtoms; ++i) {
      Atom atom = m_molecule->atom(i);
      fcoords.push_back(m_unitcell->toFractional(atom.position3d()));
      atomicNumsi.push_back(atom.atomicNumber());
      cout << "atom " << i << endl;
      cout << "  " << atomicNumsi.at(i) << endl;
      cout << "  " << fcoords.at(i).x() << " " << fcoords.at(i).y() << " " << fcoords.at(i).x() << endl;

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

    cout << "  " << ptr->hall_symbol << " | " << ptr->hall_number << endl;
    cout << "  " << ptr->international_symbol << " | " << ptr->spacegroup_number << endl;

    cout << endl;


    return ptr->spacegroup_number;
  }



}
}
