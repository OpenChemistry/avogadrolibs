/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/ringperceiver.h>

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
