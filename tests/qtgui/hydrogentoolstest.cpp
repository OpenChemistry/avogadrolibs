/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/hydrogentools.h>
#include <avogadro/qtgui/rwmolecule.h>

using Avogadro::QtGui::HydrogenTools;
using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::RWAtom;
using Avogadro::QtGui::RWMolecule;
using namespace std::string_literals;

TEST(HydrogenToolsTest, removeAllHydrogens)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(1);
  HydrogenTools::removeAllHydrogens(mol);
  EXPECT_EQ(mol.atomCount(), 0);

  RWAtom C1 = mol.addAtom(6);
  RWAtom C2 = mol.addAtom(6);
  RWAtom C3 = mol.addAtom(6);

  mol.addBond(C1, C2, 1);
  mol.addBond(C2, C3, 1);

  RWAtom H = mol.addAtom(1);
  mol.addBond(C1, H);
  H = mol.addAtom(1);
  mol.addBond(C1, H);
  H = mol.addAtom(1);
  mol.addBond(C1, H);

  H = mol.addAtom(1);
  mol.addBond(C2, H);
  H = mol.addAtom(1);
  mol.addBond(C2, H);

  H = mol.addAtom(1);
  mol.addBond(C3, H);
  H = mol.addAtom(1);
  mol.addBond(C3, H);
  H = mol.addAtom(1);
  mol.addBond(C3, H);

  HydrogenTools::removeAllHydrogens(mol);
  EXPECT_EQ("C3"s, mol.molecule().formula());
}

TEST(HydrogenToolsTest, adjustHydrogens_C3H8)
{
  Molecule m;
  RWMolecule mol(m);
  RWAtom C1 = mol.addAtom(6);
  RWAtom C2 = mol.addAtom(6);
  RWAtom C3 = mol.addAtom(6);
  mol.addBond(C1, C2, 1);
  mol.addBond(C2, C3, 1);

  HydrogenTools::adjustHydrogens(mol);
  EXPECT_EQ(11, mol.atomCount());
  EXPECT_EQ(10, mol.bondCount());
  EXPECT_EQ("C3H8"s, mol.molecule().formula());
}

TEST(HydrogenToolsTest, adjustHydrogens_C2H7NO)
{
  Molecule m;
  RWMolecule mol(m);
  RWAtom C1 = mol.addAtom(6);
  RWAtom C2 = mol.addAtom(6);
  RWAtom O1 = mol.addAtom(8);
  RWAtom N1 = mol.addAtom(7);
  mol.addBond(C1, C2, 1);
  mol.addBond(C2, O1, 1);
  mol.addBond(O1, N1, 1);

  HydrogenTools::adjustHydrogens(mol);
  EXPECT_EQ(11, mol.atomCount());
  EXPECT_EQ(10, mol.bondCount());
  EXPECT_EQ("C2H7NO"s, mol.molecule().formula());
}

TEST(HydrogenToolsTest, adjustHydrogens_C2H4O)
{
  Molecule m;
  RWMolecule mol(m);
  RWAtom C1 = mol.addAtom(6);
  RWAtom C2 = mol.addAtom(6);
  RWAtom O1 = mol.addAtom(8);
  mol.addBond(C1, C2, 1);
  mol.addBond(C2, O1, 2);

  HydrogenTools::adjustHydrogens(mol);
  EXPECT_EQ(7, mol.atomCount());
  EXPECT_EQ(6, mol.bondCount());
  EXPECT_EQ("C2H4O"s, mol.molecule().formula());
}

TEST(HydrogenToolsTest, adjustHydrogens_adjustments)
{
  for (int i = 0; i < 3; ++i) {
    HydrogenTools::Adjustment adjustment;
    std::string expectedFormula;
    switch (i) {
      case 0:
        adjustment = HydrogenTools::Add;
        expectedFormula = "C2H14";
        break;
      case 1:
        adjustment = HydrogenTools::Remove;
        expectedFormula = "C2H5";
        break;
      case 2:
        adjustment = HydrogenTools::AddAndRemove;
        expectedFormula = "C2H8";
        break;
    }

    Molecule m;
    RWMolecule mol(m);
    RWAtom C1 = mol.addAtom(6); // Overbond this atom
    mol.addBond(C1, mol.addAtom(1));
    mol.addBond(C1, mol.addAtom(1));
    mol.addBond(C1, mol.addAtom(1));
    mol.addBond(C1, mol.addAtom(1));
    mol.addBond(C1, mol.addAtom(1));
    mol.addBond(C1, mol.addAtom(1));
    mol.addBond(C1, mol.addAtom(1));
    mol.addBond(C1, mol.addAtom(1));
    mol.addBond(C1, mol.addAtom(1));
    mol.addBond(C1, mol.addAtom(1));
    RWAtom C2 = mol.addAtom(6); // Underbond this atom
    mol.addBond(C2, mol.addAtom(1));

    EXPECT_EQ("C2H11"s, mol.molecule().formula());
    HydrogenTools::adjustHydrogens(mol, adjustment);
    EXPECT_EQ(expectedFormula, mol.molecule().formula());
  }
}

TEST(HydrogenToolsTest, valencyAdjustment_C)
{
  Molecule m;
  RWMolecule mol(m);
  RWAtom C = mol.addAtom(6);
  int expectedAdjustment = 4;
  for (int i = 0; i < 8; ++i, --expectedAdjustment) {
    EXPECT_EQ(expectedAdjustment, HydrogenTools::valencyAdjustment(C));
    mol.addBond(mol.addAtom(1), C, 1);
  }
}

TEST(HydrogenToolsTest, valencyAdjustment_N)
{
  Molecule m;
  RWMolecule mol(m);
  RWAtom N = mol.addAtom(7);
  int expectedAdjustment = 3;
  for (int i = 0; i < 8; ++i, --expectedAdjustment) {
    if (i == 5) // neutral N can have 3 or 5 bonds in our valence model.
      EXPECT_EQ(0, HydrogenTools::valencyAdjustment(N));
    else
      EXPECT_EQ(expectedAdjustment, HydrogenTools::valencyAdjustment(N));
    mol.addBond(mol.addAtom(1), N, 1);
  }
}

TEST(HydrogenToolsTest, valencyAdjustment_O)
{
  Molecule m;
  RWMolecule mol(m);
  RWAtom O = mol.addAtom(8);
  int expectedAdjustment = 2;
  for (int i = 0; i < 8; ++i, --expectedAdjustment) {
    EXPECT_EQ(expectedAdjustment, HydrogenTools::valencyAdjustment(O));
    mol.addBond(mol.addAtom(1), O, 1);
  }
}
