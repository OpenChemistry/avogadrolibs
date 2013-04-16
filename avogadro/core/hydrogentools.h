/******************************************************************************

  This source file is part of the MoleQueue project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_CORE_HYDROGENTOOLS_H
#define AVOGADRO_CORE_HYDROGENTOOLS_H

#include "avogadrocoreexport.h"

#include <avogadro/core/vector.h>

#include <vector>

namespace Avogadro {
namespace Core {
class Atom;
class Molecule;

class AVOGADROCORE_EXPORT HydrogenTools
{
public:

  /**
   * Remove all hydrogen atoms from @a molecule.
   */
  static void removeAllHydrogens(Molecule &molecule);

  /**
   * Add/remove hydrogens on @a molecule to satisfy valency.
   */
  static void fixupHydrogens(Molecule &molecule);

  /**
   * @return The number of bonds that need to be added or removed from
   * @a atom to satisfy valency. A positive number indicates the number of
   * bonds to add, a negative number indicates the number of bonds that need to
   * be removed.
   */
  static int valencyAdjustment(const Atom &atom);

  /**
   * Obtain the indices of hydrogens that can be removed from @a atom.
   * @param atom The atom from which to prune hydrogens.
   * @param numberOfHydrogens The maximum number of hydrogens to prune.
   * @param indices A vector that will be appended with the indices of the
   * hydrogens to remove.
   * @return The number of hydrogen indices appended to @a indices.
   * @note This function modifies neither @a atom nor its parent molecule. It
   * only pushes the indices of hydrogens to remove to the end of @a indices.
   */
  static int extraHydrogenIndices(const Atom &atom, int numberOfHydrogens,
                                  std::vector<size_t> &indices);

  /**
   * Generate positions for @a numberOfHydrogens hydrogens bonded to @a atom.
   * @param positions Vector of positions that will be appended with @a
   * numberOfHydrogens hydrogen locations.
   * @note There is nothing intelligent going on here. The new positions are
   * randomly oriented and have a length that is the sum of @a atom's and
   * hydrogen's covalent radii. Effort is made to prevent overlap with other
   * bonded atoms, but this is not guaranteed.
   */
  static void generateNewHydrogenPositions(
      const Atom &atom, int numberOfHydrogens, std::vector<Vector3> &positions);

private:
  HydrogenTools(); // Not implemented
  ~HydrogenTools(); // Not implemented
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_HYDROGENTOOLS_H
