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
   * If the algorithm succeeds, the hall number will be set in the molecule.
   *
   * @param mol The molecule to be handled.
   * @param cartTol The cartesian tolerance for spglib.
   * @return The Hall number for the crystal.
   */
  static unsigned short getHallNumber(Molecule& mol,
                                      double cartTol = 1e-5);

  /**
   * Use spglib to reduce the crystal to a primitive cell. Unless the molecule
   * is missing its unit cell, it will be edited by spglib. Positions are
   * not idealized.
   *
   * If the algorithm succeeds, the hall number will be set in the molecule.
   *
   * @param mol The molecule to be reduced to its primitive cell.
   * @param cartTol The cartesian tolerance for spglib.
   * @return False if the molecule has no unit cell or if the
                   spglib algorithm failed. True otherwise.
   */
  static bool reduceToPrimitive(Molecule& mol, double cartTol = 1e-5);

  /**
   * Use spglib to refine the crystal to its conventional cell. Unless the
   * molecule is missing its unit cell, it will be edited by spglib. Positions
   * are idealized.
   *
   * If the algorithm succeeds, the hall number will be set in the molecule.
   *
   * @param mol The molecule to be conventionalized.
   * @param cartTol The cartesian tolerance for spglib.
   * @return False if the molecule has no unit cell or if the
   *         spglib algorithm failed. True otherwise.
   */
  static bool conventionalizeCell(Molecule& mol, double cartTol = 1e-5);

  /**
   * Use spglib to symmetrize the crystal. Unless the molecule is missing
   * its unit cell, it will be edited by spglib. It will be reduced
   * to its primitive form, and positions will be idealized.
   *
   * If the algorithm succeeds, the hall number will be set in the molecule.
   *
   * @param mol The molecule to be conventionalized.
   * @param cartTol The cartesian tolerance for spglib.
   * @return False if the molecule has no unit cell or if the
   *         spglib algorithm failed. True otherwise.
   */
  static bool symmetrize(Molecule& mol, double cartTol = 1e-5);

private:
  // Called by reduceToPrimitive(), conventionalizeCell(), and symmetrize()
  // Calls spg_standardize_cell()
  static bool standardizeCell(Molecule& mol, double cartTol, bool toPrimitive,
                              bool idealize);
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_AVO_SPGLIB_H
