/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/angleiterator.h>
#include <avogadro/core/molecule.h>

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
