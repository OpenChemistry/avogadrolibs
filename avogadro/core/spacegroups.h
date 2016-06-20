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
enum CrystalSystem { None, Triclinic, Monoclinic, Orthorhombic, Tetragonal,
                     Trigonal, Rhombohedral, Hexagonal, Cubic };

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
  static const char * schoenflies(unsigned short hallNumber);

  /**
   * Get the Hall symbol for a given hall number. '=' is used instead of '"'.
   * If an invalid hall number is given, an empty string will be returned.
   */
  static const char * hallSymbol(unsigned short hallNumber);

  /**
   * Get the international symbol for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   */
  static const char * international(unsigned short hallNumber);

  /**
   * Get the full international symbol for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   */
  static const char * internationalFull(unsigned short hallNumber);

  /**
   * Get the short international symbol for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   */
  static const char * internationalShort(unsigned short hallNumber);

  /**
   * Get the setting for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   * An empty string may also be returned if there are no settings for this
   * space group.
   */
  static const char * setting(unsigned short hallNumber);
};

} // end Core namespace
} // end Avogadro namespace

#endif //AVOGADRO_CORE_SPACE_GROUPS_H
