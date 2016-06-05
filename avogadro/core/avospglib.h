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

#ifndef AVOGADRO_CORE_AVOSPGLIB_H
#define AVOGADRO_CORE_AVOSPGLIB_H

#include "avogadrocore.h"

#include "array.h"
#include "vector.h"
#include "matrix.h"

#define AVOSPGLIB_TOL 0.1


namespace Avogadro {
namespace Core {
  class UnitCell;
  class Molecule;
    extern "C" {
#include <spglib/spglib.h>
    }

/**
 * @class AvoSpglib unitcell.h <avogadro/core/avospglib.h>
 * @brief The AvoSpglib class provides an interface to the external
 *        spacegroup library Spglib.
 */
class AVOGADROCORE_EXPORT AvoSpglib
  {

    public:
      /**
       * Return the spacegroup number of the crystal described by the
       * arguments.
       *
       * @param cartTol Tolerance in same units as cellMatrix.
       *
       * @return Spacegroup number if found, 0 otherwise.
       */
      static unsigned int getSpacegroup(Molecule &molecule, const double cartTol = AVOSPGLIB_TOL);

      //grab rotations and translations from spglib
      static void setRotations(Molecule &molecule, const int hallNumber);

      //return primitve unit cell and positions
      static unsigned int reduceToPrimitive(Molecule &molecule, Matrix3 &primCell, Array<Vector3> &pos, Array<unsigned char> &nums,const double cartTol = AVOSPGLIB_TOL);
      static unsigned int refineCell(Molecule &molecule, Matrix3 &symmCell, Array<Vector3> &pos, Array<unsigned char> &nums,const double cartTol = AVOSPGLIB_TOL);


    private:
      AvoSpglib();  //not implemented
      ~AvoSpglib(); //not implemented

      //populate types for use with spglib
      //should lattice, positions and types be static members?
      static void prepareMolecule(Molecule &molecule,
                           double lattice[3][3],
                           double positions[][3],
                           int    types[]);


  };

} //Core namespace
} //Avogadro namespace
#endif // AVOGADRO_CORE_AVOSPGLIB_H
