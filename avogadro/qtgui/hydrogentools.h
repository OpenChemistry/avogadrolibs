/******************************************************************************
  This source file is part of the MoleQueue project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_HYDROGENTOOLS_H
#define AVOGADRO_QTGUI_HYDROGENTOOLS_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <vector>

namespace Avogadro {
namespace QtGui {
class RWAtom;
class RWMolecule;

class AVOGADROQTGUI_EXPORT HydrogenTools
{
public:
  /**
   * Remove all hydrogen atoms from @a molecule.
   */
  static void removeAllHydrogens(RWMolecule& molecule);

  /**
   * Enum values that control the adjustHydrogen function's behavior.
   */
  enum Adjustment
  {
    /** Only add hydrogens to underbonded atoms. */
    Add = 0,
    /** Only remove hydrogens from overbonded atoms. */
    Remove,
    /** Add hydrogens to underbonded atoms and remove hydrogens from
     * overbonded atoms. */
    AddAndRemove
  };

  /**
   * Add/remove hydrogens on @a molecule to satisfy valency.
   */
  static void adjustHydrogens(RWMolecule& molecule,
                              Adjustment adjustment = AddAndRemove);

  /**
  * Add/remove hydrogens on @a atom to satisfy valency.
  */
  static void adjustHydrogens(RWAtom& atom,
                              Adjustment adjustment = AddAndRemove);

  /**
   * @return The number of bonds that need to be added or removed from
   * @a atom to satisfy valency. A positive number indicates the number of
   * bonds to add, a negative number indicates the number of bonds that need to
   * be removed.
   */
  static int valencyAdjustment(const RWAtom& atom);

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
  static int extraHydrogenIndices(const RWAtom& atom, int numberOfHydrogens,
                                  std::vector<size_t>& indices);

  /**
   * Generate positions for @a numberOfHydrogens hydrogens bonded to @a atom.
   * @param positions Vector of positions that will be appended with @a
   * numberOfHydrogens hydrogen locations.
   * @note There is nothing intelligent going on here. The new positions are
   * randomly oriented and have a length that is the sum of @a atom's and
   * hydrogen's covalent radii. Effort is made to prevent overlap with other
   * bonded atoms, but this is not guaranteed.
   */
  static void generateNewHydrogenPositions(const RWAtom& atom,
                                           int numberOfHydrogens,
                                           std::vector<Vector3>& positions);

private:
  HydrogenTools();  // Not implemented
  ~HydrogenTools(); // Not implemented
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_HYDROGENTOOLS_H
