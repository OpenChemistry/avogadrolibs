/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_SPACE_GROUPS_H
#define AVOGADRO_CORE_SPACE_GROUPS_H

#include "avogadrocoreexport.h"

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
   * @return The hall number of the matching space group string or 0 if not
   * found
   */
  static unsigned short hallNumber(const std::string& spaceGroup);

  /**
   * @return an enum representing the crystal system for a given hall number.
   * If an invalid hall number is given, None will be returned.
   */
  static CrystalSystem crystalSystem(unsigned short hallNumber);

  /**
   * @return the international number for a given hall number.
   * If an invalid hall number is given, 0 will be returned.
   */
  static unsigned short internationalNumber(unsigned short hallNumber);

  /**
   * @return the Schoenflies symbol for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   */
  static const char* schoenflies(unsigned short hallNumber);

  /**
   * @return the Hall symbol for a given hall number. '=' is used instead of
   * '"'. If an invalid hall number is given, an empty string will be returned.
   */
  static const char* hallSymbol(unsigned short hallNumber);

  /**
   * @return the international symbol for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   */
  static const char* international(unsigned short hallNumber);

  /**
   * @return the full international symbol for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   */
  static const char* internationalFull(unsigned short hallNumber);

  /**
   * @return the short international symbol for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   */
  static const char* internationalShort(unsigned short hallNumber);

  /**
   * @return the setting for a given hall number.
   * If an invalid hall number is given, an empty string will be returned.
   * An empty string may also be returned if there are no settings for this
   * space group.
   */
  static const char* setting(unsigned short hallNumber);

  /**
   * @return the number of transforms for a given hall number.
   * If an invalid hall number is given, 0 will be returned.
   */
  static unsigned short transformsCount(unsigned short hallNumber);

  /**
   * @return an array of transforms for a given hall number and a vector v.
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
                           double cartTol = 1e-5, bool wrapToCell = true,
                           bool allCopies = true);

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

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_SPACE_GROUPS_H
