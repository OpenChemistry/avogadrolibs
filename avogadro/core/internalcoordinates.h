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
 * Where a z-matrix over a molecule would need a dummy atom.
 *
 * A z-matrix cannot describe a linear fragment. With a row's atom, its
 * distance reference and its angle reference in a line, the 180 degree angle
 * pins nothing down, no dihedral measured from that row can be
 * reconstructed, and neither value can be edited: there is no plane to open
 * the angle in and no axis the torsion would turn the atom about. The remedy
 * chemists have always used is a dummy atom set off the axis, which gives
 * those rows a right angle and a plane to be measured against.
 */
struct DummyAtomSite
{
  /** The atom the dummy belongs beside, and should be bonded to. */
  Index anchor = MaxIndex;
  /** Where the dummy goes: off the linear axis, beside @a anchor. */
  Vector3 position = Vector3::Zero();
};

/**
 * The dummy atoms @p molecule needs before its z-matrix is complete.
 *
 * Only fragments where no real atom lies off the axis need one. A linear
 * unit with something bent hanging off it -- the alkyne of a tolan, the
 * methyl of a propyne -- is already describable against its own atoms and
 * yields nothing here. A wholly linear molecule such as diacetylene yields
 * one site per atom the straight rows hang from.
 *
 * Nothing is added to the molecule: the caller places the atoms, so that the
 * change is one the person asked for and can undo.
 *
 * @param molecule The molecule to inspect.
 * @param distance How far from its anchor each dummy is placed, in Angstroms.
 * @return One site per atom needing a dummy, in z-matrix row order.
 */
AVOGADROCORE_EXPORT Array<DummyAtomSite> linearDummySites(
  const Molecule& molecule, Real distance = 1.0);

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
 * The order the rows of a generated z-matrix are taken in.
 */
enum class ZMatrixOrder
{
  /**
   * Order the rows for the best-conditioned z-matrix, walking outwards in
   * bond order from the lowest-indexed atom. Rows are then not necessarily
   * in the molecule's atom order.
   */
  Optimal,
  /**
   * Keep the molecule's own atom order where it makes a z-matrix no worse
   * than Optimal would, so that the numbering of a generated input file
   * matches the numbering the user sees. The molecule's order is kept only
   * when every atom is bonded to an earlier one (or opens its fragment) and
   * it leaves no more rows near-linear than Optimal would; otherwise the
   * Optimal order is used, and the caller sees that in @a rowToAtom.
   */
  PreferAtomOrder
};

/**
 * The rows of @p internalCoords whose references are too close to linear for
 * the row to be read or edited as an internal coordinate.
 *
 * A row is reported when its own angle, or the angle its dihedral is
 * measured about, is within @p toleranceDegrees of straight. The geometry
 * such a row describes is still correct to within rounding, but the value is
 * ill-conditioned: a thousandth of an angstrom of movement swings it by tens
 * of degrees. A caller writing a z-matrix for another program should say so.
 *
 * @param molecule The molecule the rows describe.
 * @param internalCoords Rows as returned by cartesianToInternal().
 * @param toleranceDegrees How close to 180 degrees counts as too linear.
 * @return The offending row indices, ascending.
 */
AVOGADROCORE_EXPORT Array<Index> linearReferenceRows(
  const Molecule& molecule, const Array<InternalCoordinate>& internalCoords,
  Real toleranceDegrees = 175.0);

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

/**
 * Derive a z-matrix from a molecule's Cartesian coordinates, choosing how
 * the rows are ordered.
 *
 * @param molecule The molecule to describe.
 * @param rowToAtom Filled with the atom index each row places. It is the
 * identity whenever the molecule's own atom order was kept.
 * @param order Whether to order the rows for the best-conditioned z-matrix
 * or to keep the molecule's atom order where that is no worse.
 * @return One row per atom, in z-matrix order.
 */
AVOGADROCORE_EXPORT Array<InternalCoordinate> cartesianToInternal(
  const Molecule& molecule, Array<Index>& rowToAtom, ZMatrixOrder order);

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_INTERNALCOORDINATES_H
