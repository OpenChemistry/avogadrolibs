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
   * several equally valid assignments to try first (see
   * Molecule::perceiveBondOrders()). Never changes whether a valid assignment
   * is found.
   */
  bool useGeometry = true;

  /**
   * How many branching steps the search may spend on each connected group of
   * unsaturated atoms before giving that group up. Ordinary molecules,
   * fused aromatics included, need none at all.
   */
  std::size_t stepBudgetPerComponent = 100000;
};

/** What Molecule::perceiveBondOrders() did. */
struct BondOrderResult
{
  /** True if every atom's valence was satisfied. */
  bool success = true;

  /** The atoms left unsatisfied, in increasing order. */
  std::vector<Index> failedAtoms;

  /** A human-readable explanation when @a success is false; empty otherwise. */
  std::string message;
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_BONDORDERPERCEPTION_H
