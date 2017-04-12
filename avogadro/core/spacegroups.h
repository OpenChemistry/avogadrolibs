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

#ifndef AVOGADRO_CORE_SPACE_GROUPS_H
#define AVOGADRO_CORE_SPACE_GROUPS_H

#include "avogadrocore.h"

namespace Avogadro {
namespace Core {

/**
 * Enumeration of the crystal system.
 */
enum CrystalSystem
{
  None,
  Triclinic,
  Monoclinic,
  Orthorhombic,
  Tetragonal,
  Trigonal,
  Rhombohedral,
  Hexagonal,
  Cubic
};

/**
 * @class SpaceGroups spacegroups.h <avogadro/core/spacegroups.h>
 * @brief The Spacegroups class stores basic data about crystal spacegroups.
 *
 * The spacegroups class gives a simple interface to basic data about crystal
 * spacegroups. The data is generated from information in spglib.
 */

class AVOGADROCORE_EXPORT SpaceGroups
{
public:
  SpaceGroups();
  ~SpaceGroups();

  /**
   * Get an enum representing the crystal system for a given hall number.
   * If an invalid hall number is given, None will be returned.
   */
  static CrystalSystem crystalSystem(unsigned short hallNumber);

  /**
   * Get the international number for a given hall number.
   * If an invalid hall number is given, 0 will be returned.
   */
  static unsigned short internationalNumber(unsigned short hallNumber);

  /**
   * Get the Schoenflies symbol for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   */
  static const char* schoenflies(unsigned short hallNumber);

  /**
   * Get the Hall symbol for a given hall number. '=' is used instead of '"'.
   * If an invalid hall number is given, an empty string will be returned.
   */
  static const char* hallSymbol(unsigned short hallNumber);

  /**
   * Get the international symbol for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   */
  static const char* international(unsigned short hallNumber);

  /**
   * Get the full international symbol for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   */
  static const char* internationalFull(unsigned short hallNumber);

  /**
   * Get the short international symbol for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   */
  static const char* internationalShort(unsigned short hallNumber);

  /**
   * Get the setting for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   * An empty string may also be returned if there are no settings for this
   * space group.
   */
  static const char* setting(unsigned short hallNumber);

  /**
   * Get the number of transforms for a given hall number.
   * If an invalid hall number is given, 0 will be returned.
   */
  static unsigned short transformsCount(unsigned short hallNumber);

  /**
   * Get an array of transforms for a given hall number and a vector v.
   * The vector should be in fractional coordinates.
   * If an invalid hall number is given, an empty array will be returned.
   */
  static Array<Vector3> getTransforms(unsigned short hallNumber,
                                      const Vector3& v);

  /**
   * Fill a crystal with atoms by using transforms from a hall number.
   * Nothing will be done if the molecule does not have a unit cell.
   * The cartesian tolerance is used to check if an atom is already
   * present at that location. If there is another atom within that
   * distance, the new atom will not be placed there.
   */
  static void fillUnitCell(Molecule& mol, unsigned short hallNumber,
                           double cartTol = 1e-5);

  /**
   * Reduce a cell to its asymmetric unit.
   * Nothing will be done if the molecule does not have a unit cell.
   * The cartesian tolerance is used to check if an atom is present
   * at a location within the tolerance distance.
   * If an atom is present, the atom gets removed.
   */
  static void reduceToAsymmetricUnit(Molecule& mol, unsigned short hallNumber,
                                     double cartTol = 1e-5);

private:
  /**
   * Get the transforms string stored in the database.
   */
  static const char* transformsString(unsigned short hallNumber);
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_SPACE_GROUPS_H
