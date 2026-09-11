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
   * The atoms on @p startAtom's side of @p bond, as unique ids, including
   * @p startAtom itself.
   *
   * When @p bond lies in a ring there is no such side -- every atom can be
   * reached from both ends without crossing the bond -- so the result is
   * @p startAtom alone. That keeps a ring rigid instead of tearing it open.
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
   * Where the two are bonded this is the fragment on @p movingAtom's side of
   * that bond. Where they are not -- an internal coordinate may be measured
   * against any two atoms, not only bonded ones -- there is no fragment to
   * carry along and the result is @p movingAtom alone.
   *
   * @return An empty array if either atom is invalid.
   */
  static Core::Array<Index> fragmentUniqueIds(RWMolecule& molecule,
                                              Index anchorAtom,
                                              Index movingAtom);

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
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_FRAGMENTTOOLS_H
