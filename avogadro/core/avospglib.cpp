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
    cout << "Space Group" << endl;
    cout << m_unitcell->getSpaceGroup() << endl;




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

    /*size_t numTransforms=m_unitcell->m_transformM.size();
    for (size_t i=0;i<numTransforms;++i) {
      cout << m_unitcell->m_transformM.at(i) << endl;
      cout << m_unitcell->m_transformV.at(i) << endl;
      cout << endl;
    }*/

  }

  /*bool AvoSpglib::fillUnitCell(const double cartTol)
  {

    const double tolSq = cartTol*cartTol;

    Array<Vector3> filledFcoords = Transform();
    size_t numFilled = filledFcoords.size();
    cout << numFilled << "  filled atoms" << endl;

    for (size_t i = 0; i < numFilled; ++i) {
      cout << "  " << filledFcoords.at(i).x() << " " << filledFcoords.at(i).y() << " " << filledFcoords.at(i).x() << endl;
    }

    return true;
  }*/

  // return fcoords after apply symmetry
  // transformations
  //Array<Vector3> AvoSpglib::Transform()
  bool AvoSpglib::fillUnitCell(const double cartTol)
  {
    Array<Vector3>      fOut;
    Array<unsigned char> numOut;

    //fOut.push_back(fcoords.at(0));
    static double prec=2e-5;
    size_t numAtoms = m_molecule->atomCount();
    for (size_t i = 0; i < numAtoms; ++i) {
      unsigned char thisAtom = atomicNums.at(i);

      //apply each transformation to this atom
      for (size_t t=0;t<m_unitcell->m_transformM.size();++t) {
        Vector3 tmp = m_unitcell->m_transformM.at(t)*fcoords.at(i)
          + m_unitcell->m_transformV.at(t);
        if (tmp.x() < 0.)
          tmp.x() += 1.;
        if (tmp.x() >= 1.)
          tmp.x() -= 1.;
        if (tmp.y() < 0.)
          tmp.y() += 1.;
        if (tmp.y() >= 1.)
          tmp.y() -= 1.;
        if (tmp.z() < 0.)
          tmp.z() += 1.;
        if (tmp.z() >= 1.)
          tmp.z() -= 1.;

        //If the new position is unique
        //add it to the fractional coordiantes
        bool duplicate = false;
        for (size_t j = 0;j<fOut.size();++j) {
          if (fabs(tmp.x() - fOut.at(j).x()) < prec &&
              fabs(tmp.y() - fOut.at(j).y()) < prec &&
              fabs(tmp.z() - fOut.at(j).z()) < prec)
          {
            duplicate = true;
            break;
          }
        }
        if (!duplicate) {
          numOut.push_back(thisAtom);
          fOut.push_back(tmp);
        }
      }
    }

    //make cartisian positions
    Array<Vector3> cOut;
    for (size_t i = 0; i < fOut.size(); ++i) {
      cOut.push_back(m_unitcell->toCartesian(fOut.at(i)));
      //cout << cOut.at(i).x() << " " << cOut.at(i).y() << " " << cOut.at(i).z() << endl;
    }

    //let's try to remove the original atoms and add the new ones
    m_molecule->clearAtoms();
    for (size_t i = 0; i < numOut.size(); ++i) {
      m_molecule->addAtom(numOut.at(i));
    }
    cout << numOut.size() << endl;
    cout << m_molecule->atomCount() << endl;

    m_molecule->setAtomPositions3d(cOut);

    return true;

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
    cout << "determine spagegroup" << endl;
    SpglibDataset * ptr = spg_get_dataset(lattice,
                                          positions,
                                          types,
                                          numAtoms,
                                          cartTol);
    if (!ptr || ptr->spacegroup_number == 0) {
      cout << "Cannot determine spacegroup." << endl;
        return 0;
    }

    cout << endl;
    cout << ptr->hall_symbol << " | " << ptr->hall_number << endl;
    cout << ptr->international_symbol << " | " << ptr->spacegroup_number << endl;

    cout << endl;


    return ptr->spacegroup_number;
  }



}
}
