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
#include "spglib/spglib.h"
    }

/**
 * @class AvoSpglib unitcell.h <avogadro/core/avospglib.h>
 * @brief The AvoSpglib class provides an interface to the external
 *        spacegroup library Spglib.
 */
class AVOGADROCORE_EXPORT AvoSpglib
  {

    public:
      explicit AvoSpglib(Molecule *mol = 0);
      ~AvoSpglib();

      /**
       * Return the spacegroup number of the crystal described by the
       * arguments.
       *
       * @param cartTol Tolerance in same units as cellMatrix.
       *
       * @return Spacegroup number if found, 0 otherwise.
       */
      unsigned int getSpacegroup(const double cartTol = AVOSPGLIB_TOL);
      bool fillUnitCell(const double cartTol = AVOSPGLIB_TOL);
      //unsigned int reduceToPrimitive(Array<Vector3> pos, Array<Vector3> nums,const double cartTol = AVOSPGLIB_TOL);

    private:
      Molecule *m_molecule;
      UnitCell *m_unitcell;

      //items that are given to Spglib
      Array<Vector3> fcoords;
      Array<unsigned char> atomicNums;
      Matrix3 cellMatrix;

      Array<Vector3> Transform();


  };

} //Core namespace
} //Avogadro namespace
#endif // AVOGADRO_CORE_AVOSPGLIB_H
