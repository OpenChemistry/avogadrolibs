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

#ifndef AVOGADRO_CORE_AVO_SPGLIB_H
#define AVOGADRO_CORE_AVO_SPGLIB_H

#include "avogadrocore.h"
#include "molecule.h"

namespace Avogadro {
namespace Core {

/**
 * @class AvoSpglib avospglib.h <avogadro/core/avospglib.h>
 * @brief The AvoSpglib class provides an interface between Avogadro and Spglib.
 */

class AVOGADROCORE_EXPORT AvoSpglib
{
public:
  AvoSpglib();
  ~AvoSpglib();

  /**
   * Use spglib to find the Hall number for a crystal. If the unit cell does not
   * exist or if the algorithm fails, 0 will be returned.
   *
   * @param cartTol The cartesian tolerance for spglib.
   * @return The Hall number for the crystal.
   */
  static unsigned short getHallNumber(const Molecule &mol,
                                      double cartTol = 0.05);

};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_AVO_SPGLIB_H
