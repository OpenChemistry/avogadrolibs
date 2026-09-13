/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_INTERNALCOORDINATES_H
#define AVOGADRO_CORE_INTERNALCOORDINATES_H

#include "avogadrocore.h"

#include "array.h"
#include "molecule.h"
#include "vector.h"

namespace Avogadro {
namespace Core {

/**
 * A single row of a z-matrix: the distance to atom @a a, the angle at @a a
 * to atom @a b, and the dihedral about the @a a - @a b axis to atom @a c.
 *
 * @a a, @a b and @a c are molecule atom indices, or MaxIndex where the row
 * has no such reference. The first three rows of a z-matrix necessarily have
 * fewer than three references, since there are not yet three atoms to
 * measure against.
 *
 * Angles and dihedrals are in degrees.
 */
struct InternalCoordinate
{
  Index a = MaxIndex;
  Index b = MaxIndex;
  Index c = MaxIndex;
  Real length = 0.0;
  Real angle = 0.0;
  Real dihedral = 0.0;
};

/**
 * How the opening rows of a z-matrix are anchored in Cartesian space.
 *
 * A z-matrix fixes a molecule's internal geometry but not where it sits or
 * how it is oriented: the first atom, the direction to the second, and the
 * plane of the third are all free.
 */
enum class ZMatrixOrigin
{
  /** First atom at the origin, second along +x, third in the xy-plane. */
  Canonical,
  /**
   * Take the free parameters from the molecule's current coordinates, so
   * that rebuilding a molecule that already has a geometry neither moves nor
   * reorients it.
   */
  Preserve
};

/**
 * Rebuild Cartesian coordinates from a z-matrix whose rows are in atom
 * order, so that row @a i places atom @a i.
 *
 * Each row's references must name atoms in earlier rows; a row referencing
 * an atom that has not yet been placed keeps as much of its definition as is
 * usable (a distance and an angle, or a distance alone) rather than reading
 * an unset position.
 *
 * @param molecule The molecule being rebuilt, used for its atom count.
 * @param internalCoords One row per atom, in atom order.
 * @return Positions indexed by atom index.
 */
AVOGADROCORE_EXPORT Array<Vector3> internalToCartesian(
  const Molecule& molecule, const Array<InternalCoordinate>& internalCoords);

/**
 * Rebuild Cartesian coordinates from a z-matrix whose row order differs from
 * the molecule's atom order.
 *
 * @param molecule The molecule being rebuilt.
 * @param internalCoords One row per atom, in z-matrix order.
 * @param rowToAtom The atom index each row places, as returned by
 * cartesianToInternal().
 * @param origin Whether to anchor the result canonically or on the
 * molecule's existing coordinates.
 * @return Positions indexed by atom index.
 */
AVOGADROCORE_EXPORT Array<Vector3> internalToCartesian(
  const Molecule& molecule, const Array<InternalCoordinate>& internalCoords,
  const Array<Index>& rowToAtom,
  ZMatrixOrigin origin = ZMatrixOrigin::Preserve);

/**
 * Derive a z-matrix from a molecule's Cartesian coordinates.
 *
 * Rows are returned in z-matrix order, which is not necessarily the
 * molecule's atom order: every row's references are guaranteed to name atoms
 * that appear in earlier rows, which is what makes the result a valid
 * z-matrix. @p rowToAtom maps each row back to the atom it places, and is
 * the identity when the molecule's atom order is already a valid z-matrix
 * order.
 *
 * References are drawn from bonded atoms wherever possible, so that a row's
 * length, angle and dihedral are chemically meaningful. Disconnected
 * fragments are anchored to the atoms placed before them, so the geometry of
 * a multi-fragment system is described exactly rather than fragment by
 * fragment.
 *
 * @param molecule The molecule to describe.
 * @param rowToAtom Filled with the atom index each row places.
 * @return One row per atom, in z-matrix order.
 */
AVOGADROCORE_EXPORT Array<InternalCoordinate> cartesianToInternal(
  const Molecule& molecule, Array<Index>& rowToAtom);

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_INTERNALCOORDINATES_H
