/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_KEKULIZE_H
#define AVOGADRO_CORE_KEKULIZE_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include <string>
#include <vector>

namespace Avogadro::Core {

class Molecule;

/**
 * Replace aromatic bond flags with alternating single and double bond orders.
 *
 * This is the inverse of AromaticityPerceiver: that class reads a molecule
 * already in Kekule form and says which of its bonds are aromatic; this
 * function takes a molecule whose aromatic bonds are not yet distinguished
 * into single and double and commits to one of the (possibly several) valid
 * alternations.
 *
 * Every atom incident to an aromatic bond is first classified as needing
 * exactly one double bond, or none, by asking Core::atomValence() whether it
 * has room for one more unit of bond order once its aromatic bonds are each
 * counted as contributing one. This is the chemistry a reviewer most needs to
 * check, so here is the rule applied by hand to the cases it must get right:
 *
 * | Atom                                    | current | target | double? |
 * |------------------------------------------|:-------:|:------:|:-------:|
 * | Thiophene S (two ring bonds)              |    2    |   2    |   no    |
 * | Furan O (two ring bonds)                  |    2    |   2    |   no    |
 * | Pyridine N (two ring bonds, lone pair)     |    2    |   3    |   yes   |
 * | Pyrrole [nH] N (two ring bonds + N-H)      |    3    |   3    |   no    |
 * | Benzene C (two ring bonds + H)             |    3    |   4    |   yes   |
 * | Naphthalene bridgehead C (three ring bonds)|    3    |   4    |   yes   |
 * | N-methylpyrrole N (two ring bonds + methyl)|    3    |   3    |   no    |
 * | N-methylpyridinium N+ (two ring + methyl)  |    3    |   4    |   yes   |
 * | Cyclopentadienyl [cH-] C (two ring + H)    |    3    |   3    |   no    |
 * | Tropylium [cH+] C (two ring bonds + H)     |    3    |   3    |   no    |
 * | 2-pyridone carbonyl C (two ring + exo C=O) |    4    |   4    |   no    |
 *
 * The last row is why an exocyclic double bond matters here even though this
 * function never assigns one: the carbon's bond to its oxygen is not aromatic,
 * so it counts its full order of 2, which together with its two ring bonds
 * already fills carbon's valence and leaves no room for a ring double bond.
 * Getting that wrong is what makes pyridinone the classic case toolkits
 * disagree on.
 *
 * Formally: for an atom with @a n aromatic bonds and non-aromatic bonds whose
 * orders sum to @a s,
 * @code
 *   current = s + n
 *   target  = Core::atomValence(atomicNumber, formalCharge, current)
 *   needsDouble = (current + 1 <= target)
 * @endcode
 * An atom already at or beyond its target valence -- overbonded input --
 * simply comes out not needing a double bond: the same inequality answers
 * false in that case too, since target <= current < current + 1. That is a
 * deliberate leniency rather than a validity check; overbonded input is not
 * this function's problem to reject.
 *
 * Candidate double bonds are then the aromatic bonds whose both endpoints
 * need one. An atom that needs a double bond but has no candidate at all
 * fails immediately. Otherwise this is exact cover by forced moves where
 * possible (an atom with exactly one candidate commits it, which cascades)
 * and bounded backtracking, most-constrained-atom first, over whatever forced
 * moves do not resolve. Fused aromatic systems ordinarily resolve entirely by
 * forced moves; backtracking exists for the harder cases (azulene-like
 * systems, or an odd-membered all-carbon aromatic ring, which cannot be
 * satisfied at all).
 *
 * Classification reads the molecule as it stands, and there is no separate
 * "hydrogens this atom will get later" argument. Any bond that contributes to
 * an atom's valence must therefore already be present before calling this --
 * including hydrogens whose count is known, since an N-H is what separates
 * pyrrole-type nitrogen from pyridine-type. A caller that materializes
 * hydrogens from the bond orders this produces has to do so in two passes,
 * which is what SmilesParser does.
 *
 * @param molecule The molecule to modify; bond orders are the only thing
 * changed, and only for bonds flagged aromatic. Nothing is written unless
 * every aromatic bond can be assigned.
 * @param aromaticBonds One entry per bond, true where the bond is aromatic.
 * Aromatic atoms are the atoms these bonds connect.
 * @param failedAtom If given, set to the atom that could not be satisfied when
 * this returns false, or MaxIndex if the failure was not attributable to one
 * (for example, the backtracking step budget was exhausted).
 * @return True if every aromatic bond was assigned an order.
 */
AVOGADROCORE_EXPORT bool kekulize(Molecule& molecule,
                                  const std::vector<bool>& aromaticBonds,
                                  Index* failedAtom = nullptr);

/**
 * A human readable description of why kekulize() failed, for a reader to
 * report. Shared so that every format says the same thing about the same
 * failure.
 * @param failedAtom The value kekulize() reported, MaxIndex included.
 */
AVOGADROCORE_EXPORT std::string kekulizeFailureMessage(Index failedAtom);

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_KEKULIZE_H
