/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_BONDORDERPERCEPTION_H
#define AVOGADRO_CORE_BONDORDERPERCEPTION_H

#include "avogadrocore.h"

#include <cstddef>
#include <string>
#include <vector>

namespace Avogadro::Core {

/** Settings for Molecule::perceiveBondOrders(). */
struct BondOrderOptions
{
  /**
   * Use the 3D coordinates, when the molecule has them, to decide which of
   * several equally valid assignments to try first, and to rule out a second
   * pi bond on a bent two-coordinate period-2 atom (see
   * Molecule::perceiveBondOrders()). The second use can change whether a
   * valid assignment is found: a bare C6 ring has an all-double cumulene
   * solution that geometry excludes.
   */
  bool useGeometry = true;

  /**
   * How many branching steps the search may spend on each connected group of
   * unsaturated atoms before giving that group up. Isolated double and triple
   * bonds are settled by propagation alone, but rings and other conjugated
   * systems need branching: benzene and naphthalene take one step, biphenyl
   * two, coronene five. A budget of zero therefore fails every group that
   * propagation cannot settle.
   */
  std::size_t stepBudgetPerComponent = 100000;
};

/** What Molecule::perceiveBondOrders() did. */
struct BondOrderResult
{
  /**
   * True if every atom's valence was satisfied. When false, the bonds of each
   * group of atoms that could not be solved exactly still hold a best-effort
   * partial assignment; @a failedAtoms are the atoms left short.
   */
  bool success = true;

  /** The atoms still unsatisfied after the best effort, in increasing order. */
  std::vector<Index> failedAtoms;

  /** A human-readable explanation when @a success is false; empty otherwise. */
  std::string message;
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_BONDORDERPERCEPTION_H
