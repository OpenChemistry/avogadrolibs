/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "aromaticity.h"

#include "graph.h"
#include "molecule.h"
#include "ringperceiver.h"

#include <algorithm>
#include <map>
#include <set>
#include <utility>

namespace Avogadro::Core {

namespace {

/** What the atom's double bonds, if any, are doing. */
struct BondContext
{
  bool ringDouble = false; //!< Double bond to another atom in the same ring.
  bool exocyclicDouble = false; //!< Double bond leaving the ring.
  Index connections = 0;
};

/**
 * Pi electrons this atom contributes to a ring it belongs to.
 *
 * Hand-transcribed chemistry; each case names the structure it is there for.
 * Returns NotAromaticCandidate when the atom has no p orbital to lend, which
 * disqualifies every ring it is in.
 */
signed char contribution(unsigned char atomicNumber, signed char charge,
                         const BondContext& context)
{
  switch (atomicNumber) {
    case 6: // C
      if (charge == 0) {
        if (context.ringDouble)
          return 1; // benzene
        if (context.exocyclicDouble)
          return 0; // the carbonyl of 2-pyridone, or of tropone
        return NotAromaticCandidate; // saturated, as in cyclohexane
      }
      if (charge == -1)
        return context.ringDouble ? 1 : 2; // cyclopentadienyl anion
      if (charge == 1)
        return context.ringDouble ? 1 : 0; // tropylium
      return NotAromaticCandidate;

    case 7:  // N
    case 15: // P
      if (charge == 0) {
        if (context.ringDouble)
          return 1; // pyridine
        if (context.exocyclicDouble)
          return 0; // an N-oxide drawn with a double bond
        if (context.connections == 3)
          return 2; // pyrrole
        return NotAromaticCandidate;
      }
      if (charge == 1) {
        if (context.ringDouble)
          return 1; // pyridinium
        if (context.connections == 3)
          return 2;
        return NotAromaticCandidate; // quaternary, no lone pair left
      }
      if (charge == -1)
        return 2; // deprotonated pyrrole
      return NotAromaticCandidate;

    case 8: // O
      if (charge == 0)
        return context.connections == 2 ? 2 : NotAromaticCandidate; // furan
      if (charge == 1)
        return context.ringDouble ? 1 : 0; // pyrylium
      return NotAromaticCandidate;

    case 16: // S
    case 34: // Se
      if (charge == 0) {
        if (context.exocyclicDouble)
          return 0; // a sulfoxide or sulfone in the ring
        return context.connections == 2 ? 2 : NotAromaticCandidate; // thiophene
      }
      if (charge == 1)
        return context.ringDouble ? 1 : 2;
      return NotAromaticCandidate;

    default:
      // Everything else, boron included. Borazine comes out non-aromatic,
      // which is the answer the default model is meant to give and which also
      // keeps it from depending on how the input drew the B-N bonds.
      return NotAromaticCandidate;
  }
}

bool huckel(int piElectrons)
{
  // 4n+2 for n >= 0.
  return piElectrons >= 2 && ((piElectrons - 2) % 4) == 0;
}

} // namespace

AromaticityPerceiver::AromaticityPerceiver(const Molecule* m, Model model)
  : m_molecule(m), m_model(model), m_perceived(false)
{
}

void AromaticityPerceiver::setMolecule(const Molecule* m)
{
  m_molecule = m;
  m_perceived = false;
  m_ringSystems.clear();
  m_piContributions.clear();
  m_aromaticAtoms.clear();
  m_aromaticBonds.clear();
}

const std::vector<std::vector<Index>>& AromaticityPerceiver::ringSystems() const
{
  perceive();
  return m_ringSystems;
}

const std::vector<signed char>& AromaticityPerceiver::piContributions() const
{
  perceive();
  return m_piContributions;
}

const std::vector<bool>& AromaticityPerceiver::aromaticAtoms() const
{
  perceive();
  return m_aromaticAtoms;
}

const std::vector<bool>& AromaticityPerceiver::aromaticBonds() const
{
  perceive();
  return m_aromaticBonds;
}

void AromaticityPerceiver::perceive() const
{
  if (m_perceived)
    return;
  m_perceived = true;

  if (m_molecule == nullptr)
    return;

  const Index atomCount = m_molecule->atomCount();
  const Index bondCount = m_molecule->bondCount();
  const Array<std::pair<Index, Index>>& pairs = m_molecule->bondPairs();
  const Array<unsigned char>& orders = m_molecule->bondOrders();
  const Array<unsigned char>& numbers = m_molecule->atomicNumbers();

  m_piContributions.assign(atomCount, NotAromaticCandidate);
  m_aromaticAtoms.assign(atomCount, false);
  m_aromaticBonds.assign(bondCount, false);
  if (atomCount == 0)
    return;

  RingPerceiver perceiver(m_molecule);
  const std::vector<std::vector<size_t>>& rings = perceiver.rings();
  if (rings.empty())
    return;

  // Which bonds close a ring. Every bond between atoms adjacent in some
  // smallest ring qualifies, which is what separates a double bond inside the
  // ring from one leaving it.
  std::vector<bool> ringBond(bondCount, false);
  std::map<std::pair<Index, Index>, Index> bondLookup;
  for (Index bond = 0; bond < bondCount; ++bond) {
    const std::pair<Index, Index>& ends = pairs[bond];
    bondLookup[{ std::min(ends.first, ends.second),
                 std::max(ends.first, ends.second) }] = bond;
  }
  const auto findBond = [&](Index a, Index b) -> Index {
    const auto it = bondLookup.find({ std::min(a, b), std::max(a, b) });
    return it == bondLookup.end() ? MaxIndex : it->second;
  };

  for (const std::vector<size_t>& ring : rings) {
    for (size_t i = 0; i < ring.size(); ++i) {
      const Index bond = findBond(ring[i], ring[(i + 1) % ring.size()]);
      if (bond != MaxIndex)
        ringBond[bond] = true;
    }
  }

  // Per-atom pi contribution.
  std::vector<BondContext> context(atomCount);
  for (Index bond = 0; bond < bondCount; ++bond) {
    const std::pair<Index, Index>& ends = pairs[bond];
    ++context[ends.first].connections;
    ++context[ends.second].connections;
    if (orders[bond] != 2)
      continue;
    if (ringBond[bond]) {
      context[ends.first].ringDouble = true;
      context[ends.second].ringDouble = true;
    } else {
      context[ends.first].exocyclicDouble = true;
      context[ends.second].exocyclicDouble = true;
    }
  }

  std::vector<bool> inRing(atomCount, false);
  for (const std::vector<size_t>& ring : rings)
    for (size_t atom : ring)
      inRing[atom] = true;

  for (Index atom = 0; atom < atomCount; ++atom) {
    if (!inRing[atom])
      continue;
    m_piContributions[atom] = contribution(
      numbers[atom], m_molecule->formalCharge(atom), context[atom]);
  }

  // Fused ring systems: connected components of the ring bonds.
  std::vector<Index> system(atomCount, MaxIndex);
  Index systemCount = 0;
  for (Index seed = 0; seed < atomCount; ++seed) {
    if (!inRing[seed] || system[seed] != MaxIndex)
      continue;
    std::vector<Index> queue(1, seed);
    system[seed] = systemCount;
    m_ringSystems.emplace_back();
    while (!queue.empty()) {
      const Index atom = queue.back();
      queue.pop_back();
      m_ringSystems.back().push_back(atom);
      for (Index bond : m_molecule->graph().edges(atom)) {
        if (!ringBond[bond])
          continue;
        const std::pair<Index, Index>& ends = pairs[bond];
        const Index other = (ends.first == atom) ? ends.second : ends.first;
        if (system[other] == MaxIndex) {
          system[other] = systemCount;
          queue.push_back(other);
        }
      }
    }
    ++systemCount;
  }

  // A set of atoms is aromatic when every one can contribute and the total
  // satisfies Huckel. Individual rings are tested first, then whole fused
  // systems, which is what catches azulene.
  std::set<Index> aromatic;
  const auto test = [&](const std::vector<Index>& atoms) {
    int total = 0;
    for (Index atom : atoms) {
      if (m_piContributions[atom] == NotAromaticCandidate)
        return;
      total += m_piContributions[atom];
    }
    if (huckel(total))
      aromatic.insert(atoms.begin(), atoms.end());
  };

  for (const std::vector<size_t>& ring : rings)
    test(std::vector<Index>(ring.begin(), ring.end()));
  for (const std::vector<Index>& fused : m_ringSystems) {
    if (fused.size() > 1)
      test(fused);
  }

  for (Index atom : aromatic)
    m_aromaticAtoms[atom] = true;

  for (Index bond = 0; bond < bondCount; ++bond) {
    const std::pair<Index, Index>& ends = pairs[bond];
    m_aromaticBonds[bond] = ringBond[bond] && m_aromaticAtoms[ends.first] &&
                            m_aromaticAtoms[ends.second];
  }
}

} // namespace Avogadro::Core
