/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_SPACE_GROUPS_H
#define AVOGADRO_CORE_SPACE_GROUPS_H

#include "avogadrocoreexport.h"

#include "array.h"
#include "vector.h"

#include <string>
#include <vector>

namespace Avogadro::Core {

class Molecule;

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
  SpaceGroups() = default;
  ~SpaceGroups() = default;

  /**
   * @return The hall number of the matching space group string or 0 if not
   * found
   *
   * Besides the strings in the table (Hall symbol, international symbols),
   * this accepts the spellings other programs write: screw axes without the
   * underscore ("P 63 m c", "P 1 21/c 1"), a trailing setting that selects an
   * origin choice or the hexagonal / rhombohedral axes ("F d -3 m :2",
   * "R -3 m :H"), the pre-1983 cubic notation ("I m 3 m") and a bare
   * international table number ("229").
   *
   * A symbol or number that fits several settings (origin choice, axes) is
   * not guessed: 0 is returned. See internationalNumberFromString().
   */
  static unsigned short hallNumber(const std::string& spaceGroup);

  /**
   * @return the hall number whose Hall symbol is exactly @p hallSymbol, or 0
   * if there is none.
   *
   * Unlike hallNumber(), the international symbols and numbers are not
   * accepted: a string that is not a Hall symbol of the table gives 0. Runs of
   * white space are collapsed and a double quote is read as '=', as in the
   * table, so "-P  2yn" and "P 3 2\"" (the table's "P 3 2=") match.
   */
  static unsigned short hallNumberFromHallSymbol(const std::string& hallSymbol);

  /**
   * @return the hall number of the space group whose symmetry operations are
   * exactly @p operations, or 0 if no entry of the table has this set.
   *
   * This is how most crystallography programs resolve a setting: the symmetry
   * operations a CIF file lists identify the origin choice and axes (which an
   * H-M symbol often leaves out), and cannot disagree with the coordinates.
   *
   * Each operation is written like "x,y,z", "-x+1/2,y,-z", "1/2+x,y,z" or
   * "x-y,x,z+1/6". Letters may be upper case, spaces and quotes are ignored,
   * and constants may be decimals (0.5, 0.3333, 0.6667) if they are close to a
   * multiple of 1/12. Translations are taken modulo one. The order of the
   * operations and repeats do not matter. All operations must be present and
   * none may be extra. Text that is not an operation, or an empty list,
   * gives 0.
   *
   * Three pairs of entries in the table (hall numbers 322 and 324, 326 and 328,
   * 330 and 332, all group 68) have the same operations and the same Hall
   * symbol, and differ only in a setting label. The lower number is returned.
   */
  static unsigned short hallNumberFromTransforms(
    const std::vector<std::string>& operations);

  /**
   * @return the international table number (1-230) that the string refers to,
   * even if hallNumber() cannot pick one setting for it (e.g. "74"), or 0 if
   * the string is not recognized.
   */
  static unsigned short internationalNumberFromString(
    const std::string& spaceGroup);

  /**
   * @return the key of the Molecule data map entry (an int) in which file
   * readers keep the international table number of a space group whose Hall
   * number is ambiguous. It is never written to files: the file writers and the
   * molecular properties table skip it.
   */
  static const char* internationalNumberKey();

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
                           bool allCopies = false);

  /**
   * Add translational copies of atoms on the unit cell boundary.
   * For atoms at fractional coordinate ~0, a copy is placed at ~1 and
   * vice versa, plus edge and corner combinations.
   * No symmetry operations are applied.
   */
  static void fillTranslationalCopies(Molecule& mol, double cartTol = 1e-5);

  /**
   * Reduce a cell to its asymmetric unit.
   * Nothing will be done if the molecule does not have a unit cell.
   * The cartesian tolerance is used to check if an atom is present
   * at a location within the tolerance distance.
   * If an atom is present, the atom gets removed.
   */
  static void reduceToAsymmetricUnit(Molecule& mol, unsigned short hallNumber,
                                     double cartTol = 1e-5);

  /**
   * Get indices of translationally unique atoms, filtering out duplicates.
   * Atoms with fractional coordinates near 1.0 that duplicate atoms near 0.0
   * (due to periodic boundary conditions) are excluded.
   * @param mol The molecule with a unit cell
   * @param tolerance Fractional coordinate tolerance for duplicate detection
   * @return Array of atom indices to include (empty if no unit cell)
   */
  static Array<Index> translationalUniqueAtoms(const Molecule& mol,
                                               double tolerance = 0.001);

private:
  /**
   * Get the transforms string stored in the database.
   */
  static const char* transformsString(unsigned short hallNumber);
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_SPACE_GROUPS_H
