/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_FRAGMENTTOOLS_H
#define AVOGADRO_QTGUI_FRAGMENTTOOLS_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/array.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/vector.h>

#include <QtCore/QString>

#include <Eigen/Geometry>

#include <array>

namespace Avogadro {
namespace QtGui {

class RWAtom;
class RWBond;
class RWMolecule;

/**
 * @class FragmentTools fragmenttools.h <avogadro/qtgui/fragmenttools.h>
 * @brief Find the part of a molecule that one end of an internal coordinate
 * can move independently of the rest, and move it.
 *
 * Editing a bond length, angle or torsion means moving everything on one
 * side of it and leaving the other side alone, so that the rest of the
 * molecule -- and where the molecule sits in the view -- stays put. These
 * collect that side and apply a transform to it.
 *
 * Atoms are named by unique id rather than index, so a fragment stays valid
 * across the edits made while moving it.
 */
class AVOGADROQTGUI_EXPORT FragmentTools
{
public:
  /**
   * The outcome of a chain edit (setChainDistance(), setChainAngle(),
   * setChainTorsion()).
   *
   * Ok is the only outcome that changed anything. The others each name a
   * distinct reason the edit could not be carried out, so a caller such as
   * the Measure tool can explain the refusal rather than just reporting
   * failure:
   * - InvalidAtoms: an atom does not exist, or two of them are the same.
   * - InvalidValue: the requested length or angle is not a usable number
   *   (NaN, infinite, or a negative length).
   * - Ring: a bond on the chain exists but is part of a ring, so the side
   *   of it that would need to move cannot be separated from the rest.
   * - NotRigid: the end atoms share a molecule but nothing along the chain
   *   is bonded, so there is no side of anything to move independently.
   * - Degenerate: the atoms are positioned so the coordinate itself is not
   *   well defined -- coincident atoms for a distance, or a collinear
   *   arrangement for an angle or a torsion.
   */
  enum class CoordinateEditResult
  {
    Ok,
    InvalidAtoms,
    InvalidValue,
    Ring,
    NotRigid,
    Degenerate
  };

  /**
   * The atoms that move with @p startAtom when @p bond is manipulated, as
   * unique ids, including @p startAtom itself.
   *
   * For an ordinary bond that is everything on @p startAtom's side of it.
   * When @p bond lies in a ring there is no such side, since every ring atom
   * is reachable from both ends without crossing the bond; the ring itself
   * then stays rigid, but whatever hangs off @p startAtom and is held by
   * nothing else -- its hydrogens and other substituents -- still comes
   * along.
   *
   * @param molecule The molecule to walk.
   * @param bond The bond whose two sides are being separated.
   * @param startAtom The end of @p bond whose side is wanted.
   */
  static Core::Array<Index> fragmentUniqueIds(RWMolecule& molecule,
                                              const RWBond& bond,
                                              const RWAtom& startAtom);

  /**
   * The atoms that move when @p movingAtom is moved relative to
   * @p anchorAtom, as unique ids.
   *
   * An internal coordinate may be measured against any two atoms, not only
   * bonded ones, so this covers three cases:
   * - Bonded: the fragment is @p movingAtom's side of that bond.
   * - Not bonded, and the two atoms are not connected by any path of
   *   bonds at all: there is nothing on @p anchorAtom's side holding
   *   @p movingAtom in place, so the whole of @p movingAtom's molecule is
   *   the fragment. This is what lets editing one atom of a water dimer's
   *   second molecule move that whole molecule rigidly.
   * - Not bonded, but the two share a molecule some other way: this is an
   *   explicit edit against a user-chosen reference elsewhere in the same
   *   molecule, so only @p movingAtom itself moves.
   *
   * @return An empty array if either atom is invalid.
   */
  static Core::Array<Index> fragmentUniqueIds(RWMolecule& molecule,
                                              Index anchorAtom,
                                              Index movingAtom);

  /**
   * Apply @p transform to every atom named in @p uniqueIds.
   *
   * The moves are pushed individually, so a caller that wants them to undo
   * as one step is responsible for the surrounding merge scope. Use this
   * from a caller that already holds one -- an interactive drag, say, whose
   * whole gesture should undo at once.
   */
  static void transformAtoms(RWMolecule& molecule,
                             const Core::Array<Index>& uniqueIds,
                             const Eigen::Affine3d& transform);

  /**
   * Apply @p transform to every atom named in @p uniqueIds, as a single
   * undo command titled @p undoText.
   */
  static void transformAtoms(RWMolecule& molecule,
                             const Core::Array<Index>& uniqueIds,
                             const Eigen::Affine3d& transform,
                             const QString& undoText);

  /**
   * Set one internal coordinate, moving @p atom and the fragment attached to
   * it and leaving everything else -- including where the molecule sits in
   * the view -- alone.
   *
   * The arguments are in the order a z-matrix row names them, and it is the
   * first atom, the one the row places, that moves.
   *
   * @return False, changing nothing, if an atom is invalid, if two of them
   * are the same, or if the geometry is too degenerate to define the
   * coordinate -- coincident atoms for a distance, a collinear arrangement
   * for an angle or a torsion.
   * @{
   */
  static bool setDistance(RWMolecule& molecule, Index atom, Index a,
                          Real length);
  static bool setAngle(RWMolecule& molecule, Index atom, Index a, Index b,
                       Real degrees);
  static bool setTorsion(RWMolecule& molecule, Index atom, Index a, Index b,
                         Index c, Real degrees);
  /** @} */

  /**
   * Set one internal coordinate, moving exactly @p fragment.
   *
   * The geometry these reach is the same as the overloads above -- the same
   * distance, angle or torsion, measured the same way round -- but the
   * caller says what moves to get there. Which part of the molecule *should*
   * move is a question about the edit, not about the coordinate: placing a
   * z-matrix row moves only the atom that row places, while twisting a
   * torsion in a table rotates the whole side of the central bond so the
   * geometry around it stays rigid.
   *
   * Pass a fragment from fragmentUniqueIds().
   *
   * @return False, changing nothing, in every case the fragment-free
   * overloads above refuse, and also if @p fragment does not contain the
   * atom actually named to move -- the ring case above, where a bond has no
   * side of its own. It also refuses if @p fragment contains a reference
   * atom the transform would move regardless of the fragment: @p a for
   * setDistance() (a translation moves everything given to it), @p b for
   * setAngle() (the rotation only leaves the pivot @p a fixed) and @p c for
   * setTorsion() (the rotation only leaves the @p a-@p b axis fixed). The
   * pivot and axis atoms themselves may be in @p fragment -- the property
   * table's angle fragment always contains the vertex -- only the *other*
   * reference atom may not. Without this a fragment that happens to carry
   * its own reference point along would turn the edit into a silent no-op.
   * @{
   */
  static bool setDistance(RWMolecule& molecule, Index atom, Index a,
                          Real length, const Core::Array<Index>& fragment);
  static bool setAngle(RWMolecule& molecule, Index atom, Index a, Index b,
                       Real degrees, const Core::Array<Index>& fragment);
  static bool setTorsion(RWMolecule& molecule, Index atom, Index a, Index b,
                         Index c, Real degrees,
                         const Core::Array<Index>& fragment);
  /** @} */

  /**
   * Set one internal coordinate along a click-ordered chain of atoms, named
   * by unique id: the first atom is fixed and the last one moves, matching
   * how the Measure tool collects its atoms.
   *
   * Unlike the fragment-free overloads above -- which always move only the
   * first-named atom, the z-matrix convention -- these choose a moving
   * fragment the way the property tables do: as much of the molecule as can
   * rotate or translate rigidly with the moving end. Preference order, from
   * @ref measure-tool-edit-plan.md "the design notes":
   * - distance i-j: j's side of the i-j bond; else, if i and j are in
   *   different connected components, all of j's molecule; else NotRigid.
   * - angle i-j-k: if i and k are in different components, all of k's
   *   molecule; else j's side of the i-j bond if that bond exists; else k's
   *   side of the j-k bond if that exists; else NotRigid.
   * - torsion i-j-k-l: if i and l are in different components, all of l's
   *   molecule; else k's side of the j-k bond if that exists; else NotRigid.
   * "Different components" is decided on the two end atoms only, not on
   * every link, so a vertex bonded only to the fixed end still finds a
   * moving fragment on the other side.
   *
   * @return Ok on success. Otherwise a CoordinateEditResult describing why
   * nothing moved; see its documentation for what each value means.
   * @{
   */
  static CoordinateEditResult setChainDistance(
    RWMolecule& molecule, const std::array<Index, 2>& uniqueIds, Real length);
  static CoordinateEditResult setChainAngle(
    RWMolecule& molecule, const std::array<Index, 3>& uniqueIds, Real degrees);
  static CoordinateEditResult setChainTorsion(
    RWMolecule& molecule, const std::array<Index, 4>& uniqueIds, Real degrees);
  /** @} */
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_FRAGMENTTOOLS_H
