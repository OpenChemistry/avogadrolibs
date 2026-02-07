/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/dihedraliterator.h>
#include <avogadro/core/molecule.h>

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
