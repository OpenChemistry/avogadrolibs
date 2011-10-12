#include <gtest/gtest.h>

#include "../src/molecule.h"

TEST(MoleculeTest, size)
{
  MolCore::Molecule molecule;
  EXPECT_EQ(molecule.size(), 0);
}

TEST(MoleculeTest, isEmpty)
{
  MolCore::Molecule molecule;
  EXPECT_EQ(molecule.isEmpty(), true);
}

TEST(MoleculeTest, addAtom)
{
  MolCore::Molecule molecule;
  EXPECT_EQ(molecule.atomCount(), 0);

  MolCore::Atom atom = molecule.addAtom(6);
  EXPECT_EQ(atom.isValid(), true);
  EXPECT_EQ(molecule.atomCount(), 1);
  EXPECT_EQ(atom.index(), 0);

  MolCore::Atom atom2 = molecule.addAtom(1);
  EXPECT_EQ(atom2.isValid(), true);
  EXPECT_EQ(molecule.atomCount(), 2);
  EXPECT_EQ(atom2.index(), 1);
}

TEST(MoleculeTest, addBond)
{
  MolCore::Molecule molecule;
  EXPECT_EQ(molecule.bondCount(), 0);

  MolCore::Atom a = molecule.addAtom(1);
  MolCore::Atom b = molecule.addAtom(1);
  MolCore::Bond bondAB = molecule.addBond(a, b);
  EXPECT_EQ(molecule.bondCount(), 1);
  EXPECT_EQ(bondAB.atom1().index(), a.index());
  EXPECT_EQ(bondAB.atom2().index(), b.index());
  EXPECT_EQ(bondAB.order(), 1);
}

TEST(MoleculeTest, removeBond)
{
  MolCore::Molecule molecule;
  MolCore::Atom a = molecule.addAtom(1);
  MolCore::Atom b = molecule.addAtom(1);
  MolCore::Atom c = molecule.addAtom(1);
  MolCore::Bond bondAB = molecule.addBond(a, b);
  MolCore::Bond bondBC = molecule.addBond(b, c);
  EXPECT_EQ(molecule.bondCount(), 2);
  EXPECT_EQ(bondAB.index(), 0);
  EXPECT_EQ(bondBC.index(), 1);

  molecule.removeBond(bondAB);
  EXPECT_EQ(molecule.bondCount(), 1);

  molecule.removeBond(0);
  EXPECT_EQ(molecule.bondCount(), 0);
}
