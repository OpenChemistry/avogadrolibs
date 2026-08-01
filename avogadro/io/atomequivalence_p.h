/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_ATOMEQUIVALENCE_P_H
#define AVOGADRO_IO_ATOMEQUIVALENCE_P_H

#include <avogadro/core/molecule.h>

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <utility>
#include <vector>

namespace Avogadro::Io {

/**
 * Partition the atoms of @a mol into constitutional equivalence classes by
 * Morgan-style iterative refinement: atoms start out separated by element,
 * degree, charge and isotope, and are then repeatedly re-separated by the
 * multiset of their neighbours' classes until the partition stops growing.
 *
 * Two atoms share a class when nothing about the connectivity around them
 * tells them apart. That is what makes this usable as a stereocentre test: an
 * atom whose neighbours all land in different classes has four constitutionally
 * distinct substituents.
 *
 * Known limitations, all of which lose stereocentres rather than invent them:
 *
 * - The refinement is purely constitutional, so it cannot separate branches
 *   that differ only in their own stereochemistry. Meso compounds and
 *   pseudo-asymmetric centres come out symmetric.
 * - Ring cis/trans centres share a class here even though they are
 *   stereogenic. In 4-methylcyclohexanol the two ring branches leaving C1
 *   really are constitutionally identical -- the molecule has a symmetry plane
 *   through C1 and C4 -- so this function cannot separate them. Callers that
 *   care handle it on top: the SMILES writer treats a tie between two ring
 *   neighbours as stereogenic when another such centre shares the ring system,
 *   which is what tells 4-methylcyclohexanol apart from cyclohexanol.
 *
 * The first is resolved by re-running the refinement with stereo descriptors
 * folded into the invariant until it settles. That is deliberately not done
 * here.
 *
 * Hydrogens participate like any other atom, so the caller may run this over
 * the molecule as stored without suppressing them first.
 *
 * @return A class index per atom, in the range [0, class count).
 */
inline std::vector<Index> atomEquivalenceClasses(const Core::Molecule& mol)
{
  const Index atomCount = mol.atomCount();
  std::vector<Index> classes(atomCount, 0);
  if (atomCount == 0)
    return classes;

  const Core::Array<std::pair<Index, Index>>& pairs = mol.bondPairs();
  const Core::Array<unsigned char>& numbers = mol.atomicNumbers();
  const Core::Array<unsigned char>& orders = mol.bondOrders();

  // Flat adjacency, so the refinement rounds below allocate nothing.
  std::vector<Index> start(atomCount + 1, 0);
  for (const std::pair<Index, Index>& ends : pairs) {
    ++start[ends.first + 1];
    ++start[ends.second + 1];
  }
  for (Index atom = 0; atom < atomCount; ++atom)
    start[atom + 1] += start[atom];

  std::vector<Index> neighbor(2 * pairs.size());
  std::vector<unsigned char> neighborOrder(2 * pairs.size());
  std::vector<Index> cursor(start.begin(), start.end() - 1);
  for (Index bond = 0; bond < pairs.size(); ++bond) {
    const std::pair<Index, Index>& ends = pairs[bond];
    neighborOrder[cursor[ends.first]] = orders[bond];
    neighbor[cursor[ends.first]++] = ends.second;
    neighborOrder[cursor[ends.second]] = orders[bond];
    neighbor[cursor[ends.second]++] = ends.first;
  }

  Index maxDegree = 0;
  for (Index atom = 0; atom < atomCount; ++atom)
    maxDegree = std::max(maxDegree, start[atom + 1] - start[atom]);

  // One key per atom: its own invariant, then its neighbours' sorted codes,
  // zero padded so every key compares as a fixed-width tuple.
  const Index stride = maxDegree + 1;
  std::vector<uint64_t> keys(atomCount * stride, 0);
  std::vector<Index> order(atomCount);

  const auto rankByKeys = [&]() -> Index {
    std::iota(order.begin(), order.end(), Index(0));
    std::sort(order.begin(), order.end(), [&](Index a, Index b) {
      return std::lexicographical_compare(
        keys.begin() + a * stride, keys.begin() + (a + 1) * stride,
        keys.begin() + b * stride, keys.begin() + (b + 1) * stride);
    });

    Index rank = 0;
    for (Index i = 0; i < atomCount; ++i) {
      if (i > 0 && !std::equal(keys.begin() + order[i] * stride,
                               keys.begin() + (order[i] + 1) * stride,
                               keys.begin() + order[i - 1] * stride)) {
        ++rank;
      }
      classes[order[i]] = rank;
    }
    return rank + 1;
  };

  for (Index atom = 0; atom < atomCount; ++atom) {
    keys[atom * stride] =
      (static_cast<uint64_t>(numbers[atom]) << 48) |
      (static_cast<uint64_t>(start[atom + 1] - start[atom]) << 32) |
      (static_cast<uint64_t>(mol.formalCharge(atom) + 128) << 16) |
      static_cast<uint64_t>(mol.isotope(atom));
  }
  Index classCount = rankByKeys();

  // Each round can only split classes, so the count is strictly increasing
  // until it settles; it cannot exceed the atom count.
  for (Index round = 0; round < atomCount; ++round) {
    for (Index atom = 0; atom < atomCount; ++atom) {
      uint64_t* key = &keys[atom * stride];
      key[0] = classes[atom];
      Index slot = 1;
      for (Index e = start[atom]; e < start[atom + 1]; ++e) {
        key[slot++] =
          (static_cast<uint64_t>(classes[neighbor[e]]) << 8) | neighborOrder[e];
      }
      std::sort(key + 1, key + slot);
      for (; slot < stride; ++slot)
        key[slot] = 0;
    }

    const Index refined = rankByKeys();
    if (refined == classCount)
      break;
    classCount = refined;
  }

  return classes;
}

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_ATOMEQUIVALENCE_P_H
