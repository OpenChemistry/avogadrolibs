/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>

using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Molecule;

TEST(BondTest, setOrder)
{
  Molecule molecule;
  Atom a = molecule.addAtom(1);
  Atom b = molecule.addAtom(1);
  Bond bond = molecule.addBond(a, b);
  EXPECT_EQ(bond.order(), 1);

  // change the bonds's order
  bond.setOrder(2);
  EXPECT_EQ(bond.order(), 2);
}

TEST(BondTest, operators)
{
  Molecule molecule;
  Atom atom1 = molecule.addAtom(1);
  Atom atom2 = molecule.addAtom(2);
  Atom atom3 = molecule.addAtom(3);
  Bond bond1 = molecule.addBond(atom1, atom2, 1);
  Bond bond2 = molecule.addBond(atom2, atom3, 2);

  EXPECT_TRUE(bond1 == molecule.bond(0));
  EXPECT_FALSE(bond1 != molecule.bond(0));
  EXPECT_TRUE(bond1 != molecule.bond(1));
  EXPECT_FALSE(bond1 == molecule.bond(1));
  EXPECT_TRUE(bond1 != bond2);
}
