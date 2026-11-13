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

TEST(BondTest, outOfRangeProxies)
{
  Molecule molecule;
  Atom a = molecule.addAtom(6);
  Atom b = molecule.addAtom(8);
  molecule.addBond(a, b, 1);
  Atom c = molecule.addAtom(1);

  // out-of-range indices give invalid proxies, not out-of-bounds ones
  EXPECT_TRUE(molecule.atom(2).isValid());
  EXPECT_FALSE(molecule.atom(3).isValid());
  EXPECT_FALSE(molecule.atom(1000).isValid());
  EXPECT_TRUE(molecule.bond(0).isValid());
  EXPECT_FALSE(molecule.bond(1).isValid());
  EXPECT_FALSE(molecule.bond(1000).isValid());

  // an invalid bond hands back invalid atoms rather than crashing
  Bond none = molecule.bond(a, c);
  EXPECT_FALSE(none.isValid());
  EXPECT_FALSE(none.atom1().isValid());
  EXPECT_FALSE(none.atom2().isValid());

  Bond defaultBond;
  EXPECT_FALSE(defaultBond.isValid());
  EXPECT_FALSE(defaultBond.atom1().isValid());
  EXPECT_FALSE(defaultBond.atom2().isValid());

  Bond past = molecule.bond(5);
  EXPECT_FALSE(past.atom1().isValid());
}
