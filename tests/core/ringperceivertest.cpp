/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/ringperceiver.h>

#include <algorithm>
#include <utility>
#include <vector>

using Avogadro::Core::Molecule;
using Avogadro::Core::RingPerceiver;

TEST(RingPerceiverTest, benzene)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(molecule.atom(0), molecule.atom(1), 1);
  molecule.addBond(molecule.atom(1), molecule.atom(2), 2);
  molecule.addBond(molecule.atom(2), molecule.atom(3), 1);
  molecule.addBond(molecule.atom(3), molecule.atom(4), 2);
  molecule.addBond(molecule.atom(4), molecule.atom(5), 1);
  molecule.addBond(molecule.atom(5), molecule.atom(0), 2);

  RingPerceiver perceiver(&molecule);
  std::vector<std::vector<size_t>> rings = perceiver.rings();
  EXPECT_EQ(rings.size(), static_cast<size_t>(1));
  EXPECT_EQ(rings[0].size(), static_cast<size_t>(6));
}

TEST(RingPerceiverTest, ethanol)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(8);
  molecule.addBond(molecule.atom(0), molecule.atom(1), 1);
  molecule.addBond(molecule.atom(1), molecule.atom(2), 1);

  RingPerceiver perceiver(&molecule);
  std::vector<std::vector<size_t>> rings = perceiver.rings();
  EXPECT_EQ(rings.size(), static_cast<size_t>(0));
}

TEST(RingPerceiverTest, naphthalene)
{
  // Naphthalene: two fused 6-membered rings, 10 carbons
  //   0-1-2-3-4-5-0  (ring 1)
  //   4-5-6-7-8-9-4  ... but fused at bond 4-5
  // Actually: 0-1-2-3-4-5-0 and 5-4-9-8-7-6-5
  Molecule molecule;
  for (int i = 0; i < 10; ++i)
    molecule.addAtom(6);

  // Ring 1: 0-1-2-3-4-5-0
  molecule.addBond(molecule.atom(0), molecule.atom(1), 1);
  molecule.addBond(molecule.atom(1), molecule.atom(2), 1);
  molecule.addBond(molecule.atom(2), molecule.atom(3), 1);
  molecule.addBond(molecule.atom(3), molecule.atom(4), 1);
  molecule.addBond(molecule.atom(4), molecule.atom(5), 1);
  molecule.addBond(molecule.atom(5), molecule.atom(0), 1);
  // Ring 2 (fused at 4-5): 4-9-8-7-6-5
  molecule.addBond(molecule.atom(4), molecule.atom(9), 1);
  molecule.addBond(molecule.atom(9), molecule.atom(8), 1);
  molecule.addBond(molecule.atom(8), molecule.atom(7), 1);
  molecule.addBond(molecule.atom(7), molecule.atom(6), 1);
  molecule.addBond(molecule.atom(6), molecule.atom(5), 1);

  RingPerceiver perceiver(&molecule);
  std::vector<std::vector<size_t>> rings = perceiver.rings();
  EXPECT_EQ(rings.size(), static_cast<size_t>(2));
  for (const auto& ring : rings)
    EXPECT_EQ(ring.size(), static_cast<size_t>(6));
}

TEST(RingPerceiverTest, cyclopropane)
{
  // 3-membered ring: C-C-C
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(molecule.atom(0), molecule.atom(1), 1);
  molecule.addBond(molecule.atom(1), molecule.atom(2), 1);
  molecule.addBond(molecule.atom(2), molecule.atom(0), 1);

  RingPerceiver perceiver(&molecule);
  std::vector<std::vector<size_t>> rings = perceiver.rings();
  EXPECT_EQ(rings.size(), static_cast<size_t>(1));
  EXPECT_EQ(rings[0].size(), static_cast<size_t>(3));
}

TEST(RingPerceiverTest, spiro)
{
  // Spiro[4.4]nonane: two 5-membered rings sharing atom 0
  // Ring A: 0-1-2-3-4-0
  // Ring B: 0-5-6-7-8-0
  Molecule molecule;
  for (int i = 0; i < 9; ++i)
    molecule.addAtom(6);

  // Ring A
  molecule.addBond(molecule.atom(0), molecule.atom(1), 1);
  molecule.addBond(molecule.atom(1), molecule.atom(2), 1);
  molecule.addBond(molecule.atom(2), molecule.atom(3), 1);
  molecule.addBond(molecule.atom(3), molecule.atom(4), 1);
  molecule.addBond(molecule.atom(4), molecule.atom(0), 1);
  // Ring B
  molecule.addBond(molecule.atom(0), molecule.atom(5), 1);
  molecule.addBond(molecule.atom(5), molecule.atom(6), 1);
  molecule.addBond(molecule.atom(6), molecule.atom(7), 1);
  molecule.addBond(molecule.atom(7), molecule.atom(8), 1);
  molecule.addBond(molecule.atom(8), molecule.atom(0), 1);

  RingPerceiver perceiver(&molecule);
  std::vector<std::vector<size_t>> rings = perceiver.rings();
  EXPECT_EQ(rings.size(), static_cast<size_t>(2));
  for (const auto& ring : rings)
    EXPECT_EQ(ring.size(), static_cast<size_t>(5));
}

TEST(RingPerceiverTest, cubane)
{
  // Cubane: 8 vertices, 12 edges forming a cube
  // Bottom: 0-1-2-3, Top: 4-5-6-7
  // Verticals: 0-4, 1-5, 2-6, 3-7
  Molecule molecule;
  for (int i = 0; i < 8; ++i)
    molecule.addAtom(6);

  // Bottom face edges
  molecule.addBond(molecule.atom(0), molecule.atom(1), 1);
  molecule.addBond(molecule.atom(1), molecule.atom(2), 1);
  molecule.addBond(molecule.atom(2), molecule.atom(3), 1);
  molecule.addBond(molecule.atom(3), molecule.atom(0), 1);
  // Top face edges
  molecule.addBond(molecule.atom(4), molecule.atom(5), 1);
  molecule.addBond(molecule.atom(5), molecule.atom(6), 1);
  molecule.addBond(molecule.atom(6), molecule.atom(7), 1);
  molecule.addBond(molecule.atom(7), molecule.atom(4), 1);
  // Vertical edges
  molecule.addBond(molecule.atom(0), molecule.atom(4), 1);
  molecule.addBond(molecule.atom(1), molecule.atom(5), 1);
  molecule.addBond(molecule.atom(2), molecule.atom(6), 1);
  molecule.addBond(molecule.atom(3), molecule.atom(7), 1);

  RingPerceiver perceiver(&molecule);
  std::vector<std::vector<size_t>> rings = perceiver.rings();
  // SSSR of a cube has 5 independent rings (E - V + 1 = 12 - 8 + 1 = 5)
  EXPECT_EQ(rings.size(), static_cast<size_t>(5));
  for (const auto& ring : rings)
    EXPECT_EQ(ring.size(), static_cast<size_t>(4));
}

TEST(RingPerceiverTest, emptyMolecule)
{
  Molecule molecule;
  RingPerceiver perceiver(&molecule);
  std::vector<std::vector<size_t>> rings = perceiver.rings();
  EXPECT_EQ(rings.size(), static_cast<size_t>(0));
}

namespace {

using Edges = std::vector<std::pair<size_t, size_t>>;

// Build a carbon-only molecule from a bond list (bonds only, no coordinates).
Molecule fromEdges(size_t atoms, const Edges& edges)
{
  Molecule molecule;
  for (size_t i = 0; i < atoms; ++i)
    molecule.addAtom(6);
  for (const auto& e : edges)
    molecule.addBond(molecule.atom(e.first), molecule.atom(e.second), 1);
  return molecule;
}

// Sorted ring sizes of the perceived rings.
std::vector<size_t> ringSizes(Molecule& molecule)
{
  RingPerceiver perceiver(&molecule);
  std::vector<size_t> sizes;
  for (const auto& ring : perceiver.rings())
    sizes.push_back(ring.size());
  std::sort(sizes.begin(), sizes.end());
  return sizes;
}

// Every consecutive pair (and the closing pair) of a ring must be bonded.
void expectRingsAreCycles(Molecule& molecule)
{
  RingPerceiver perceiver(&molecule);
  for (const auto& ring : perceiver.rings()) {
    for (size_t i = 0; i < ring.size(); ++i) {
      size_t a = ring[i];
      size_t b = ring[(i + 1) % ring.size()];
      EXPECT_TRUE(molecule.graph().containsEdge(a, b));
    }
  }
}

Edges cycle(size_t first, size_t count)
{
  Edges e;
  for (size_t i = 0; i < count; ++i)
    e.emplace_back(first + i, first + (i + 1) % count);
  return e;
}

} // namespace

TEST(RingPerceiverTest, benzenePlusCounterion)
{
  // Benzene plus an isolated Na+: E = 6, V = 7, so E - V + 1 = 0 but the
  // cyclomatic number E - V + C = 6 - 7 + 2 = 1. Expect 1 x 6.
  Molecule molecule = fromEdges(7, cycle(0, 6));
  EXPECT_EQ(ringSizes(molecule), (std::vector<size_t>{ 6 }));
}

TEST(RingPerceiverTest, twoDisconnectedBenzenes)
{
  // E = 12, V = 12, C = 2: cyclomatic number 2. Expect 2 x 6.
  Edges e = cycle(0, 6);
  Edges e2 = cycle(6, 6);
  e.insert(e.end(), e2.begin(), e2.end());
  Molecule molecule = fromEdges(12, e);
  EXPECT_EQ(ringSizes(molecule), (std::vector<size_t>{ 6, 6 }));
  expectRingsAreCycles(molecule);
}

TEST(RingPerceiverTest, ringPlusDisconnectedChain)
{
  // Cyclopropane + a three-atom chain: E = 5, V = 6, C = 2 -> 1 ring.
  Edges e = cycle(0, 3);
  e.emplace_back(3, 4);
  e.emplace_back(4, 5);
  Molecule molecule = fromEdges(6, e);
  EXPECT_EQ(ringSizes(molecule), (std::vector<size_t>{ 3 }));
}

TEST(RingPerceiverTest, naphthaleneSizes)
{
  // Two fused 6-membered rings sharing the 0-5 bond: 2 x 6.
  Edges e = cycle(0, 6);
  e.emplace_back(0, 6);
  e.emplace_back(6, 7);
  e.emplace_back(7, 8);
  e.emplace_back(8, 9);
  e.emplace_back(9, 5);
  Molecule molecule = fromEdges(10, e);
  EXPECT_EQ(ringSizes(molecule), (std::vector<size_t>{ 6, 6 }));
  expectRingsAreCycles(molecule);
}

TEST(RingPerceiverTest, norbornane)
{
  // Bicyclo[2.2.1]heptane. Bridgeheads 0 and 3; bridges 1-2, 4-5 and 6.
  // E = 8, V = 7, rank 2. The SSSR is two 5-membered rings (the 6-membered
  // envelope is not in the SSSR).
  Edges e = { { 0, 1 }, { 1, 2 }, { 2, 3 }, { 3, 4 },
              { 4, 5 }, { 5, 0 }, { 0, 6 }, { 6, 3 } };
  Molecule molecule = fromEdges(7, e);
  EXPECT_EQ(ringSizes(molecule), (std::vector<size_t>{ 5, 5 }));
  expectRingsAreCycles(molecule);
}

TEST(RingPerceiverTest, spiroDecane)
{
  // Spiro[4.5]decane: spiro atom 0 shared by a 5-ring (0-4) and a
  // 6-ring (0, 5-9). Expect 5 + 6.
  Edges e = cycle(0, 5);
  e.emplace_back(0, 5);
  e.emplace_back(5, 6);
  e.emplace_back(6, 7);
  e.emplace_back(7, 8);
  e.emplace_back(8, 9);
  e.emplace_back(9, 0);
  Molecule molecule = fromEdges(10, e);
  EXPECT_EQ(ringSizes(molecule), (std::vector<size_t>{ 5, 6 }));
  expectRingsAreCycles(molecule);
}

TEST(RingPerceiverTest, adamantane)
{
  // Adamantane C10: four CH (0-3) and six CH2 (4-9) bridges, each CH2
  // joining a pair of CH. E = 12, V = 10, rank 3: SSSR is 3 x 6 (the fourth
  // six-membered ring is dependent).
  Edges e = { { 4, 0 }, { 4, 1 }, { 5, 0 }, { 5, 2 }, { 6, 0 }, { 6, 3 },
              { 7, 1 }, { 7, 2 }, { 8, 1 }, { 8, 3 }, { 9, 2 }, { 9, 3 } };
  Molecule molecule = fromEdges(10, e);
  EXPECT_EQ(ringSizes(molecule), (std::vector<size_t>{ 6, 6, 6 }));
  expectRingsAreCycles(molecule);
}

TEST(RingPerceiverTest, cubaneCycles)
{
  // Cubane has rank 5; the SSSR is five of the six 4-membered faces.
  Edges e = { { 0, 1 }, { 1, 2 }, { 2, 3 }, { 3, 0 }, { 4, 5 }, { 5, 6 },
              { 6, 7 }, { 7, 4 }, { 0, 4 }, { 1, 5 }, { 2, 6 }, { 3, 7 } };
  Molecule molecule = fromEdges(8, e);
  EXPECT_EQ(ringSizes(molecule), (std::vector<size_t>(5, 4)));
  expectRingsAreCycles(molecule);
}

TEST(RingPerceiverTest, bicyclooctane)
{
  // Bicyclo[2.2.2]octane: bridgeheads 0 and 1 joined by three 2-atom bridges
  // (2-3, 4-5, 6-7). Rank 2; every pair of bridges gives a 6-ring, so the
  // SSSR is 2 x 6 (the third 6-ring is dependent).
  Edges e = { { 0, 2 }, { 2, 3 }, { 3, 1 }, { 0, 4 }, { 4, 5 },
              { 5, 1 }, { 0, 6 }, { 6, 7 }, { 7, 1 } };
  Molecule molecule = fromEdges(8, e);
  EXPECT_EQ(ringSizes(molecule), (std::vector<size_t>{ 6, 6 }));
  expectRingsAreCycles(molecule);
}

TEST(RingPerceiverTest, bicyclononane)
{
  // Bicyclo[3.3.1]nonane: bridgeheads 0 and 1; bridges 2-3-4, 5-6-7 and 8.
  // Rank 2; 6-ring (via the one-atom bridge) twice; the 8-ring is dependent.
  Edges e = { { 0, 2 }, { 2, 3 }, { 3, 4 }, { 4, 1 }, { 0, 5 },
              { 5, 6 }, { 6, 7 }, { 7, 1 }, { 0, 8 }, { 8, 1 } };
  Molecule molecule = fromEdges(9, e);
  EXPECT_EQ(ringSizes(molecule), (std::vector<size_t>{ 6, 6 }));
  expectRingsAreCycles(molecule);
}
