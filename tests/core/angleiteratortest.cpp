/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/angleiterator.h>
#include <avogadro/core/graph.h>
#include <avogadro/core/molecule.h>

#include <algorithm>
#include <set>
#include <tuple>

using Avogadro::Index;
using Avogadro::Core::Angle;
using Avogadro::Core::AngleIterator;
using Avogadro::Core::Molecule;

namespace {

int countAngles(const Molecule& mol)
{
  AngleIterator it(&mol);
  Angle angle = it.begin();
  AngleIterator endIt(&mol);
  Angle end = endIt.end();
  int count = 0;
  while (angle != end) {
    ++count;
    angle = ++it;
  }
  return count;
}

// Build a chain/ring of carbons (indices 0..nC-1) and saturate with H.
void buildHydrocarbon(Molecule& mol, int nC, bool ring)
{
  for (int i = 0; i < nC; ++i)
    mol.addAtom(6);
  for (int i = 0; i + 1 < nC; ++i)
    mol.addBond(mol.atom(i), mol.atom(i + 1), 1);
  if (ring)
    mol.addBond(mol.atom(nC - 1), mol.atom(0), 1);
  for (int i = 0; i < nC; ++i) {
    int nH = (ring || (i > 0 && i < nC - 1)) ? 2 : 3;
    for (int h = 0; h < nH; ++h) {
      Avogadro::Core::Atom hydrogen = mol.addAtom(1);
      mol.addBond(mol.atom(i), hydrogen, 1);
    }
  }
}

// Independent enumeration straight from the bond graph.
std::set<std::tuple<Index, Index, Index>> expectedAngles(const Molecule& mol)
{
  std::set<std::tuple<Index, Index, Index>> result;
  for (Index b = 0; b < mol.atomCount(); ++b) {
    const auto& n = mol.graph().neighbors(b);
    for (size_t x = 0; x < n.size(); ++x)
      for (size_t y = x + 1; y < n.size(); ++y)
        result.insert(
          std::make_tuple(std::min(n[x], n[y]), b, std::max(n[x], n[y])));
  }
  return result;
}

} // namespace

TEST(AngleIteratorTest, emptyMolecule)
{
  Molecule mol;
  EXPECT_EQ(countAngles(mol), 0);
}

TEST(AngleIteratorTest, singleAtom)
{
  Molecule mol;
  mol.addAtom(6);
  EXPECT_EQ(countAngles(mol), 0);
}

TEST(AngleIteratorTest, twoAtoms)
{
  // Just one bond, not enough for an angle
  Molecule mol;
  mol.addAtom(6);
  mol.addAtom(6);
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  EXPECT_EQ(countAngles(mol), 0);
}

TEST(AngleIteratorTest, water)
{
  // O bonded to 2 H: one angle H-O-H
  Molecule mol;
  mol.addAtom(8); // O, index 0
  mol.addAtom(1); // H, index 1
  mol.addAtom(1); // H, index 2
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(0), mol.atom(2), 1);

  EXPECT_EQ(countAngles(mol), 1);
}

TEST(AngleIteratorTest, propane)
{
  // C0-C1-C2: middle atom has 2 neighbors -> 1 angle
  Molecule mol;
  mol.addAtom(6);
  mol.addAtom(6);
  mol.addAtom(6);
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(1), mol.atom(2), 1);

  EXPECT_EQ(countAngles(mol), 1);
}

TEST(AngleIteratorTest, methane)
{
  // C bonded to 4 H: C(4,2) = 6 angles
  Molecule mol;
  mol.addAtom(6); // C, index 0
  mol.addAtom(1); // H, index 1
  mol.addAtom(1); // H, index 2
  mol.addAtom(1); // H, index 3
  mol.addAtom(1); // H, index 4
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(0), mol.atom(2), 1);
  mol.addBond(mol.atom(0), mol.atom(3), 1);
  mol.addBond(mol.atom(0), mol.atom(4), 1);

  EXPECT_EQ(countAngles(mol), 6);
}

TEST(AngleIteratorTest, benzene)
{
  // Each C in benzene has 2 neighbors -> 1 angle per C -> 6 angles total
  Molecule mol;
  for (int i = 0; i < 6; ++i)
    mol.addAtom(6);
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(1), mol.atom(2), 1);
  mol.addBond(mol.atom(2), mol.atom(3), 1);
  mol.addBond(mol.atom(3), mol.atom(4), 1);
  mol.addBond(mol.atom(4), mol.atom(5), 1);
  mol.addBond(mol.atom(5), mol.atom(0), 1);

  EXPECT_EQ(countAngles(mol), 6);
}

TEST(AngleIteratorTest, neopentane)
{
  // Central C bonded to 4 C atoms: C(4,2) = 6 angles at center
  // Each terminal C has only 1 neighbor, so no angles there
  Molecule mol;
  mol.addAtom(6); // central, index 0
  mol.addAtom(6); // index 1
  mol.addAtom(6); // index 2
  mol.addAtom(6); // index 3
  mol.addAtom(6); // index 4
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(0), mol.atom(2), 1);
  mol.addBond(mol.atom(0), mol.atom(3), 1);
  mol.addBond(mol.atom(0), mol.atom(4), 1);

  EXPECT_EQ(countAngles(mol), 6);
}

namespace {

void checkAngleContent(const Molecule& mol, size_t expectedCount)
{
  const auto expected = expectedAngles(mol);
  EXPECT_EQ(expected.size(), expectedCount);

  std::set<std::tuple<Index, Index, Index>> seen;
  AngleIterator it(&mol);
  Angle angle = it.begin();
  AngleIterator endIt(&mol);
  const Angle end = endIt.end();
  size_t total = 0;
  while (angle != end) {
    ++total;
    Index a = std::get<0>(angle);
    Index b = std::get<1>(angle);
    Index c = std::get<2>(angle);
    seen.insert(std::make_tuple(std::min(a, c), b, std::max(a, c)));
    angle = ++it;
  }
  // no duplicates, and exactly the expected angles
  EXPECT_EQ(total, expectedCount);
  EXPECT_EQ(seen, expected);
}

} // namespace

TEST(AngleIteratorTest, butaneContent)
{
  // 4 C + 10 H: every carbon has 4 neighbors -> 4 * C(4,2) = 24 angles
  Molecule mol;
  buildHydrocarbon(mol, 4, false);
  ASSERT_EQ(mol.atomCount(), 14u);
  checkAngleContent(mol, 24);
}

TEST(AngleIteratorTest, cyclohexaneContent)
{
  // 6 C + 12 H: every carbon has 4 neighbors -> 6 * C(4,2) = 36 angles
  Molecule mol;
  buildHydrocarbon(mol, 6, true);
  ASSERT_EQ(mol.atomCount(), 18u);
  checkAngleContent(mol, 36);
}
