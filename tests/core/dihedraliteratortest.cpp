/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/dihedraliterator.h>
#include <avogadro/core/graph.h>
#include <avogadro/core/molecule.h>

#include <algorithm>
#include <set>
#include <tuple>

using Avogadro::Index;
using Avogadro::Core::Dihedral;
using Avogadro::Core::DihedralIterator;
using Avogadro::Core::Molecule;

namespace {

int countDihedrals(const Molecule& mol)
{
  DihedralIterator it(&mol);
  Dihedral dih = it.begin();
  DihedralIterator endIt(&mol);
  Dihedral end = endIt.end();
  int count = 0;
  while (dih != end) {
    ++count;
    dih = ++it;
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

// Independent enumeration straight from the bond graph, canonicalised so
// that (i,j,k,l) and (l,k,j,i) are the same dihedral.
std::set<std::tuple<Index, Index, Index, Index>> expectedDihedrals(
  const Molecule& mol)
{
  std::set<std::tuple<Index, Index, Index, Index>> result;
  for (Index bi = 0; bi < mol.bondCount(); ++bi) {
    const Index j = mol.bond(bi).atom1().index();
    const Index k = mol.bond(bi).atom2().index();
    for (Index i : mol.graph().neighbors(j)) {
      if (i == k)
        continue;
      for (Index l : mol.graph().neighbors(k)) {
        if (l == j || l == i)
          continue;
        auto fwd = std::make_tuple(i, j, k, l);
        auto rev = std::make_tuple(l, k, j, i);
        result.insert(std::min(fwd, rev));
      }
    }
  }
  return result;
}

} // namespace

TEST(DihedralIteratorTest, emptyMolecule)
{
  Molecule mol;
  EXPECT_EQ(countDihedrals(mol), 0);
}

TEST(DihedralIteratorTest, twoAtoms)
{
  // Too few atoms for a dihedral (need 4)
  Molecule mol;
  mol.addAtom(6);
  mol.addAtom(6);
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  EXPECT_EQ(countDihedrals(mol), 0);
}

TEST(DihedralIteratorTest, threeAtomChain)
{
  // 3 atoms, 2 bonds -- below the minimum (4 atoms, 3 bonds)
  Molecule mol;
  mol.addAtom(6);
  mol.addAtom(6);
  mol.addAtom(6);
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(1), mol.atom(2), 1);
  EXPECT_EQ(countDihedrals(mol), 0);
}

TEST(DihedralIteratorTest, butane)
{
  // C0-C1-C2-C3: linear chain, 4 atoms, 3 bonds
  // Bond C1-C2 has C0 on one side and C3 on the other -> 1 dihedral
  Molecule mol;
  mol.addAtom(6); // 0
  mol.addAtom(6); // 1
  mol.addAtom(6); // 2
  mol.addAtom(6); // 3
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(1), mol.atom(2), 1);
  mol.addBond(mol.atom(2), mol.atom(3), 1);

  EXPECT_EQ(countDihedrals(mol), 1);
}

TEST(DihedralIteratorTest, branchedChain)
{
  // C0-C1(-C3)-C2-C4: 5 atoms, 4 bonds
  // Bond C1-C2: neighbors of C1 excl. C2 = {C0, C3}; neighbors of C2 excl. C1 =
  // {C4}
  //   -> dihedrals: C0-C1-C2-C4, C3-C1-C2-C4 = 2
  // Other bonds have terminal atoms with no extra neighbors -> 0 each
  Molecule mol;
  mol.addAtom(6); // 0
  mol.addAtom(6); // 1
  mol.addAtom(6); // 2
  mol.addAtom(6); // 3
  mol.addAtom(6); // 4
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(1), mol.atom(2), 1);
  mol.addBond(mol.atom(1), mol.atom(3), 1);
  mol.addBond(mol.atom(2), mol.atom(4), 1);

  EXPECT_EQ(countDihedrals(mol), 2);
}

TEST(DihedralIteratorTest, starTopology)
{
  // Central atom bonded to 4 terminal atoms: no dihedrals
  // (terminal atoms have no neighbors besides the central one)
  Molecule mol;
  mol.addAtom(6); // 0 center
  mol.addAtom(6); // 1
  mol.addAtom(6); // 2
  mol.addAtom(6); // 3
  mol.addAtom(6); // 4
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(0), mol.atom(2), 1);
  mol.addBond(mol.atom(0), mol.atom(3), 1);
  mol.addBond(mol.atom(0), mol.atom(4), 1);

  // Each bond: central has 3 other neighbors, terminal has 0 others
  // So no complete i-j-k-l dihedral can form
  EXPECT_EQ(countDihedrals(mol), 0);
}

TEST(DihedralIteratorTest, pentane)
{
  // C0-C1-C2-C3-C4: linear chain, 5 atoms, 4 bonds
  // Bond C1-C2: C0 on one side, C3 on the other -> 1
  // Bond C2-C3: C1 on one side, C4 on the other -> 1
  // Total: 2 + Bond C0-C1 has no extra neighbors on C0 side, C2-C3 same
  //   Actually: Bond C0-C1: atom1=C0 neighbors={C1}, excl C1={}. 0.
  //   Bond C1-C2: atom1=C1 neighbors={C0,C2}, excl C2={C0}. atom2=C2
  //   neighbors={C1,C3}, excl C1={C3}. -> 1 Bond C2-C3: atom1=C2
  //   neighbors={C1,C3}, excl C3={C1}. atom2=C3 neighbors={C2,C4}, excl
  //   C2={C4}. -> 1 Bond C3-C4: atom1=C3 neighbors={C2,C4}, excl C4={C2}.
  //   atom2=C4 neighbors={C3}, excl C3={}. 0. Total: 2
  Molecule mol;
  for (int i = 0; i < 5; ++i)
    mol.addAtom(6);
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(1), mol.atom(2), 1);
  mol.addBond(mol.atom(2), mol.atom(3), 1);
  mol.addBond(mol.atom(3), mol.atom(4), 1);

  EXPECT_EQ(countDihedrals(mol), 2);
}

namespace {

void checkDihedralContent(const Molecule& mol, size_t expectedCount)
{
  const auto expected = expectedDihedrals(mol);
  EXPECT_EQ(expected.size(), expectedCount);

  std::set<std::tuple<Index, Index, Index, Index>> seen;
  DihedralIterator it(&mol);
  Dihedral dih = it.begin();
  DihedralIterator endIt(&mol);
  const Dihedral end = endIt.end();
  size_t total = 0;
  while (dih != end) {
    ++total;
    auto fwd = dih;
    auto rev = std::make_tuple(std::get<3>(dih), std::get<2>(dih),
                               std::get<1>(dih), std::get<0>(dih));
    seen.insert(std::min(fwd, rev));
    dih = ++it;
  }
  EXPECT_EQ(total, expectedCount);
  EXPECT_EQ(seen, expected);
}

} // namespace

TEST(DihedralIteratorTest, butaneContent)
{
  // 4 C + 10 H: three C-C bonds, each with 3 x 3 end substituents = 27
  Molecule mol;
  buildHydrocarbon(mol, 4, false);
  ASSERT_EQ(mol.atomCount(), 14u);
  checkDihedralContent(mol, 27);
}

TEST(DihedralIteratorTest, cyclohexaneContent)
{
  // 6 C + 12 H: six ring C-C bonds, each with 3 x 3 substituents = 54
  Molecule mol;
  buildHydrocarbon(mol, 6, true);
  ASSERT_EQ(mol.atomCount(), 18u);
  checkDihedralContent(mol, 54);
}
