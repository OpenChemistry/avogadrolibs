/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/unitcell.h>

#include <avogadro/io/gromacsformat.h>

#include <string>

using Avogadro::Core::Molecule;
using Avogadro::Core::Residue;
using Avogadro::Io::GromacsFormat;

namespace {

const std::string groAtoms = "silicon\n"
                             "1\n"
                             "    1Si      Si    1   0.200   0.200   0.200\n";

} // namespace

TEST(GromacsTest, readBox)
{
  GromacsFormat gro;
  Molecule molecule;
  ASSERT_TRUE(gro.readString(groAtoms + "0.400   0.400   0.400\n", molecule))
    << gro.error();

  EXPECT_EQ(molecule.atomCount(), 1);
  ASSERT_NE(molecule.unitCell(), nullptr);
  EXPECT_DOUBLE_EQ(molecule.unitCell()->a(), 4.0); // nm --> Angstrom
}

// Regression test: the box line is required, but a missing or blank one was
// accepted and the molecule read without a unit cell.
TEST(GromacsTest, missingBoxFails)
{
  GromacsFormat gro;
  Molecule molecule;
  EXPECT_FALSE(gro.readString(groAtoms, molecule));
}

TEST(GromacsTest, blankBoxFails)
{
  GromacsFormat gro;
  Molecule molecule;
  EXPECT_FALSE(gro.readString(groAtoms + "\n", molecule));
}

namespace {

const std::string groCys = "Built with Packmol\n"
                           "13\n"
                           "    1CYS      N    1   3.882   2.342   1.315\n"
                           "    1CYS     H1    2   3.910   2.298   1.228\n"
                           "    1CYS     H2    3   3.958   2.331   1.381\n"
                           "    1CYS     H3    4   3.894   2.295   1.228\n"
                           "    1CYS     CA    5   3.856   2.483   1.292\n"
                           "    1CYS     HA    6   3.835   2.532   1.388\n"
                           "    1CYS     CB    7   3.973   2.555   1.224\n"
                           "    1CYS    HB1    8   4.058   2.559   1.291\n"
                           "    1CYS    HB2    9   4.001   2.501   1.133\n"
                           "    1CYS     SG   10   3.929   2.728   1.179\n"
                           "    1CYS     HG   11   4.054   2.776   1.190\n"
                           "    1CYS      C   12   3.728   2.497   1.208\n"
                           "    1CYS      O   13   3.702   2.599   1.145\n"
                           "   8.0   8.0   8.0\n";

} // namespace

TEST(GromacsTest, residueAtomNamesAndElements)
{
  GromacsFormat gro;
  Molecule molecule;
  ASSERT_TRUE(gro.readString(groCys, molecule)) << gro.error();
  ASSERT_EQ(molecule.atomCount(), 13);
  ASSERT_EQ(molecule.residueCount(), 1);

  const Residue& residue = molecule.residues()[0];
  EXPECT_EQ(residue.residueName(), "CYS");

  auto ca = residue.atomByName("CA");
  auto hg = residue.atomByName("HG");
  auto sg = residue.atomByName("SG");
  auto hb1 = residue.atomByName("HB1");
  auto n = residue.atomByName("N");
  ASSERT_TRUE(ca.isValid());
  ASSERT_TRUE(hg.isValid());
  ASSERT_TRUE(sg.isValid());
  ASSERT_TRUE(hb1.isValid());
  ASSERT_TRUE(n.isValid());
  EXPECT_EQ(ca.atomicNumber(), 6);
  EXPECT_EQ(hg.atomicNumber(), 1);
  EXPECT_EQ(sg.atomicNumber(), 16);
  EXPECT_EQ(hb1.atomicNumber(), 1);
  EXPECT_EQ(n.atomicNumber(), 7);
  EXPECT_EQ(residue.atomName(ca), "CA");
  EXPECT_EQ(residue.atomName(hb1), "HB1");

  EXPECT_TRUE(molecule.bond(n, ca).isValid());
  EXPECT_TRUE(molecule.bond(ca, molecule.atom(6)).isValid()); // CA-CB
  EXPECT_TRUE(molecule.bond(sg, hg).isValid());
  EXPECT_FALSE(molecule.bond(n, sg).isValid());
}

TEST(GromacsTest, residueNameChangeStartsNewResidue)
{
  const std::string gro = "test\n"
                          "2\n"
                          "    1ALA      N    1   0.100   0.100   0.100\n"
                          "    1GLN      N    2   0.500   0.500   0.500\n"
                          "2.0 2.0 2.0\n";
  GromacsFormat reader;
  Molecule molecule;
  ASSERT_TRUE(reader.readString(gro, molecule)) << reader.error();
  EXPECT_EQ(molecule.residueCount(), 2);
}

TEST(GromacsTest, ionUsesTwoLetterSymbol)
{
  const std::string gro = "ions\n"
                          "2\n"
                          "    1NA      NA    1   0.200   0.200   0.200\n"
                          "    2CL      CL    2   1.200   1.200   1.200\n"
                          "3.0 3.0 3.0\n";
  GromacsFormat reader;
  Molecule molecule;
  ASSERT_TRUE(reader.readString(gro, molecule)) << reader.error();
  ASSERT_EQ(molecule.atomCount(), 2);
  EXPECT_EQ(molecule.atomicNumber(0), 11);
  EXPECT_EQ(molecule.atomicNumber(1), 17);
}

// Unknown residue: the first letter of the atom name is the element. Known
// ambiguity: a two-letter element in a non-ion residue ("CL1" for chlorine in
// a ligand) is read as carbon.
TEST(GromacsTest, unknownResidueFirstLetterRule)
{
  const std::string gro = "lig\n"
                          "3\n"
                          "    1LIG    C12    1   0.200   0.200   0.200\n"
                          "    1LIG    CL1    2   0.300   0.300   0.300\n"
                          "    1LIG    1HB    3   0.400   0.400   0.400\n"
                          "3.0 3.0 3.0\n";
  GromacsFormat reader;
  Molecule molecule;
  ASSERT_TRUE(reader.readString(gro, molecule)) << reader.error();
  ASSERT_EQ(molecule.atomCount(), 3);
  EXPECT_EQ(molecule.atomicNumber(0), 6);
  EXPECT_EQ(molecule.atomicNumber(1), 6);
  EXPECT_EQ(molecule.atomicNumber(2), 1);
}
