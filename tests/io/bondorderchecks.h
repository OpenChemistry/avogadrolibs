/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_TESTS_BONDORDERCHECKS_H
#define AVOGADRO_TESTS_BONDORDERCHECKS_H

#include <avogadro/core/molecule.h>
#include <avogadro/core/ringperceiver.h>

#include <algorithm>
#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace BondOrderChecks {

using Avogadro::Index;
using Avogadro::Core::Molecule;

inline std::vector<unsigned int> orderSums(const Molecule& mol)
{
  std::vector<unsigned int> sums(mol.atomCount(), 0);
  for (Index b = 0; b < mol.bondCount(); ++b) {
    sums[mol.bondPairs()[b].first] += mol.bondOrders()[b];
    sums[mol.bondPairs()[b].second] += mol.bondOrders()[b];
  }
  return sums;
}

inline std::map<unsigned int, std::size_t> histogram(const Molecule& mol)
{
  std::map<unsigned int, std::size_t> counts;
  for (Index b = 0; b < mol.bondCount(); ++b)
    ++counts[mol.bondOrders()[b]];
  return counts;
}

/** Index of the bond joining a and b in the (identical) bond list. */
inline Index bondBetween(const Molecule& mol, Index a, Index b)
{
  return mol.bond(a, b).index();
}

/**
 * The ring-level comparison of a perceived molecule with its reference.
 *
 * Both molecules must have the same atoms and bonds in the same order. The
 * reference is a Kekule structure. For every ring of the reference whose
 * bonds alternate single, multiple (an aromatic sextet in Kekule form), the
 * perceived molecule must have the same number of multiple bonds inside that
 * ring. Every bond that is in no ring at all must have exactly the reference
 * order. Bonds that lie only in rings that do not alternate (pyrrole-type
 * rings, rings with exocyclic C=O) are otherwise unconstrained here, beyond
 * the per-atom valence that perception guarantees.
 *
 * @param ignoreAtoms bonds touching these atoms are not compared (used for
 * the region around a known failure).
 * @return an empty string if it matches, else a description of the first
 * difference.
 */
inline std::string strictDifference(
  const Molecule& reference, const Molecule& result,
  const std::vector<bool>* ignoreAtoms = nullptr)
{
  Molecule ref = reference; // RingPerceiver wants a non-const-correct handle
  Avogadro::Core::RingPerceiver perceiver(&ref);
  const auto& rings = perceiver.rings();

  std::vector<bool> inRing(ref.bondCount(), false);
  for (const auto& ring : rings) {
    for (std::size_t i = 0; i < ring.size(); ++i) {
      const Index bond = bondBetween(ref, ring[i], ring[(i + 1) % ring.size()]);
      inRing[bond] = true;
    }
  }

  auto ignored = [&](Index bond) {
    if (ignoreAtoms == nullptr)
      return false;
    return (*ignoreAtoms)[ref.bondPairs()[bond].first] ||
           (*ignoreAtoms)[ref.bondPairs()[bond].second];
  };

  for (std::size_t r = 0; r < rings.size(); ++r) {
    const auto& ring = rings[r];
    if (ring.size() % 2 != 0)
      continue;
    std::vector<Index> bonds;
    for (std::size_t i = 0; i < ring.size(); ++i)
      bonds.push_back(bondBetween(ref, ring[i], ring[(i + 1) % ring.size()]));
    bool alternates = true;
    bool skip = false;
    for (std::size_t i = 0; i < bonds.size(); ++i) {
      const bool multiple = ref.bondOrders()[bonds[i]] > 1;
      const bool nextMultiple =
        ref.bondOrders()[bonds[(i + 1) % bonds.size()]] > 1;
      if (multiple == nextMultiple)
        alternates = false;
      if (ignored(bonds[i]))
        skip = true;
    }
    if (!alternates || skip)
      continue;
    std::size_t want = 0, got = 0;
    for (Index bond : bonds) {
      want += (ref.bondOrders()[bond] > 1) ? 1 : 0;
      got += (result.bondOrders()[bond] > 1) ? 1 : 0;
    }
    if (want != got) {
      return "ring " + std::to_string(r) + " (" + std::to_string(ring.size()) +
             " atoms, first atom " + std::to_string(ring[0]) + ") has " +
             std::to_string(got) + " multiple bonds, reference has " +
             std::to_string(want);
    }
  }

  for (Index b = 0; b < ref.bondCount(); ++b) {
    if (inRing[b] || ignored(b))
      continue;
    if (ref.bondOrders()[b] != result.bondOrders()[b]) {
      return "non-ring bond " + std::to_string(ref.bondPairs()[b].first) + "-" +
             std::to_string(ref.bondPairs()[b].second) + " has order " +
             std::to_string(result.bondOrders()[b]) + ", reference has " +
             std::to_string(ref.bondOrders()[b]);
    }
  }
  return std::string();
}

} // namespace BondOrderChecks

#endif
