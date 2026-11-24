/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/io/xyzformat.h>

#include <fstream>
#include <sstream>
#include <string>

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::Io::XyzFormat;

// methane.xyz uses atomic symbols to identify atoms
TEST(XyzTest, readAtomicSymbols)
{
  XyzFormat xyz;
  Molecule molecule;
  EXPECT_TRUE(xyz.readFile(AVOGADRO_DATA "/data/xyz/methane.xyz", molecule));
  ASSERT_EQ(xyz.error(), std::string());

  EXPECT_EQ(molecule.atomCount(), 5);

  // Bond perception will result in 4 bonds
  EXPECT_EQ(molecule.bondCount(), 4);

  EXPECT_EQ(molecule.atom(0).atomicNumber(), 6);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(4).atomicNumber(), 1);

  EXPECT_EQ(molecule.atom(4).position3d().x(), -0.51336);
  EXPECT_EQ(molecule.atom(4).position3d().y(), 0.88916);
  EXPECT_EQ(molecule.atom(4).position3d().z(), -0.36300);
}

TEST(XyzTest, readTotalEnergy)
{
  {
    // Open Babel
    XyzFormat xyz;
    Molecule molecule;
    std::string str = "1\nEnergy: NaN\nAr 0.0 0.0 0.0\n";
    ASSERT_TRUE(xyz.readString(str, molecule));
    EXPECT_FALSE(molecule.hasData("totalEnergy")) << str;
  }
  {
    // xtb
    XyzFormat xyz;
    Molecule molecule;
    std::string str = "1\nenergy: -123.456\nAr 0.0 0.0 0.0\n";
    ASSERT_TRUE(xyz.readString(str, molecule));
    ASSERT_TRUE(molecule.hasData("totalEnergy")) << str;
    EXPECT_EQ(molecule.data("totalEnergy").toDouble(), -123.456) << str;
  }
  {
    // orca
    XyzFormat xyz;
    Molecule molecule;
    std::string str = "1\n E -1.23456E+2\nAr 0.0 0.0 0.0\n";
    ASSERT_TRUE(xyz.readString(str, molecule));
    ASSERT_TRUE(molecule.hasData("totalEnergy")) << str;
    EXPECT_EQ(molecule.data("totalEnergy").toDouble(), -123.456) << str;
  }
}

// Some programs write coordinates with an exponent a double cannot hold, e.g.
// "2.61793E-500". Those are effectively zero and must not abort the read.
TEST(XyzTest, readUnderflowedCoordinates)
{
  XyzFormat xyz;
  Molecule molecule;
  std::string str = "2\nframe 1\n"
                    "Ar 0.0 0.0 0.0\n"
                    "Ar 0.0 0.0 4.0\n"
                    "2\nframe 2\n"
                    "Ar 2.61793E-500 0.0 0.0\n"
                    "Ar 0.0 -7.5467E-6000 4.0\n";
  ASSERT_TRUE(xyz.readString(str, molecule));
  EXPECT_EQ(xyz.error(), std::string());

  EXPECT_EQ(molecule.atomCount(), 2);
  EXPECT_EQ(molecule.coordinate3dCount(), 2);
  EXPECT_EQ(molecule.coordinate3d(1)[0].x(), 0.0);
  EXPECT_EQ(molecule.coordinate3d(1)[1].y(), 0.0);
  EXPECT_EQ(molecule.coordinate3d(1)[1].z(), 4.0);
}

TEST(XyzTest, readZeroAtomsNoHang)
{
  XyzFormat xyz;
  Molecule molecule;
  std::string str = "0\ncomment\n0\n";
  EXPECT_TRUE(xyz.readString(str, molecule));
  EXPECT_TRUE(xyz.error().empty());
  EXPECT_EQ(molecule.atomCount(), 0);
}

// Turn off the option to perceive bonds
TEST(XyzTest, readAtomicSymbolsNoBonds)
{
  XyzFormat xyz;
  xyz.setOptions("{ \"perceiveBonds\": false }");
  Molecule molecule;
  EXPECT_TRUE(xyz.readFile(AVOGADRO_DATA "/data/xyz/methane.xyz", molecule));
  ASSERT_EQ(xyz.error(), std::string());

  EXPECT_EQ(molecule.atomCount(), 5);

  // We turned off bond perception, so there should be zero bonds
  EXPECT_EQ(molecule.bondCount(), 0);

  EXPECT_EQ(molecule.atom(0).atomicNumber(), 6);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(4).atomicNumber(), 1);

  EXPECT_EQ(molecule.atom(4).position3d().x(), -0.51336);
  EXPECT_EQ(molecule.atom(4).position3d().y(), 0.88916);
  EXPECT_EQ(molecule.atom(4).position3d().z(), -0.36300);
}

// An options string this format cannot use falls back to the default rather
// than throwing out of the JSON lookup.
TEST(XyzTest, unusableOptionsFallBackToDefaults)
{
  for (const char* options : { "", "{ this is not json ", "[1, 2, 3]",
                               "{ \"perceiveBonds\": \"false\" }" }) {
    XyzFormat xyz;
    xyz.setOptions(options);
    Molecule molecule;
    ASSERT_TRUE(xyz.readFile(AVOGADRO_DATA "/data/xyz/methane.xyz", molecule))
      << options;

    // perceiveBonds defaults to on, so methane comes back with its four bonds.
    EXPECT_EQ(molecule.atomCount(), 5) << options;
    EXPECT_EQ(molecule.bondCount(), 4) << options;
  }
}

// methane-num.xyz uses atomic numbers to identify atoms
TEST(XyzTest, readAtomicNumbers)
{
  XyzFormat xyz;
  Molecule molecule;
  xyz.readFile(AVOGADRO_DATA "/data/xyz/methane-num.xyz", molecule);

  EXPECT_EQ(molecule.atomCount(), 5);

  // Bond perception will result in 4 bonds
  EXPECT_EQ(molecule.bondCount(), 4);

  EXPECT_EQ(molecule.atom(0).atomicNumber(), 6);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 1);
  EXPECT_EQ(molecule.atom(4).atomicNumber(), 1);

  EXPECT_EQ(molecule.atom(4).position3d().x(), -0.51336);
  EXPECT_EQ(molecule.atom(4).position3d().y(), 0.88916);
  EXPECT_EQ(molecule.atom(4).position3d().z(), -0.36300);
}

// Crystallography tools (e.g. Mercury) export atom labels rather than plain
// symbols. Those used to read back as InvalidElement, which poisoned the
// electron count and the formula.
TEST(XyzTest, readAtomLabels)
{
  XyzFormat xyz;
  Molecule molecule;
  std::string str = "6\nWERPOY\n"
                    "N1   0.0 0.0 0.0\n"
                    "C12  1.5 0.0 0.0\n"
                    "S1   3.0 0.0 0.0\n"
                    "CL1  4.5 0.0 0.0\n"
                    "Cl2  6.0 0.0 0.0\n"
                    "Nb1  7.5 0.0 0.0\n";
  ASSERT_TRUE(xyz.readString(str, molecule));
  ASSERT_EQ(molecule.atomCount(), 6);

  EXPECT_EQ(molecule.atom(0).atomicNumber(), 7);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 6);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), 16);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), 17);
  EXPECT_EQ(molecule.atom(4).atomicNumber(), 17);
  // The two-letter symbol must win over the one-letter one.
  EXPECT_EQ(molecule.atom(5).atomicNumber(), 41);

  EXPECT_EQ(molecule.formula(), "CCl2NNbS");
}

// Plain symbols and custom elements must not be re-interpreted by the label
// fallback, and a label with no recognizable element must not be guessed at.
TEST(XyzTest, readAtomLabelsDoesNotOverreach)
{
  XyzFormat xyz;
  Molecule molecule;
  std::string str = "4\ncomment\n"
                    "Nb  0.0 0.0 0.0\n"
                    "Xx  1.5 0.0 0.0\n"
                    "Xaa 3.0 0.0 0.0\n"
                    "Q1  4.5 0.0 0.0\n";
  ASSERT_TRUE(xyz.readString(str, molecule));
  ASSERT_EQ(molecule.atomCount(), 4);

  EXPECT_EQ(molecule.atom(0).atomicNumber(), 41);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 0);
  EXPECT_EQ(molecule.atom(2).atomicNumber(), Avogadro::CustomElementMin);
  EXPECT_EQ(molecule.atom(3).atomicNumber(), Avogadro::InvalidElement);
}

// Columns may be separated by tabs or spaces, in any mix, with CRLF endings,
// in the first frame and in every following one.
TEST(XyzTest, readMixedSeparatorsAndTrajectory)
{
  const std::string text = "2\r\nframe 0\r\n"
                           "O\t0.0\t0.0\t0.0\r\n"
                           "H  1.0 \t 0.0\t  0.5\r\n"
                           "2\r\nframe 1\r\n"
                           "O\t0.1\t0.2\t0.3\r\n"
                           "H 1.1\t0.2   0.8\r\n";
  XyzFormat xyz;
  xyz.setOptions(R"({"perceiveBonds": false})");
  Molecule molecule;
  ASSERT_TRUE(xyz.readString(text, molecule)) << xyz.error();
  ASSERT_EQ(molecule.atomCount(), 2);
  EXPECT_EQ(molecule.atom(1).atomicNumber(), 1);
  ASSERT_EQ(molecule.coordinate3dCount(), 2);
  const auto first = molecule.coordinate3d(0);
  const auto second = molecule.coordinate3d(1);
  EXPECT_EQ(first[1], Vector3(1.0, 0.0, 0.5));
  EXPECT_EQ(second[0], Vector3(0.1, 0.2, 0.3));
  EXPECT_EQ(second[1], Vector3(1.1, 0.2, 0.8));
}

// A row with fewer than three force components must be rejected, not read
// past the end of its tokens.
TEST(XyzTest, readTruncatedForceColumns)
{
  const std::string header = "2\n"
                             "Properties=species:S:1:pos:R:3:forces:R:3\n";
  XyzFormat xyz;
  xyz.setOptions(R"({"perceiveBonds": false})");
  Molecule truncated;
  EXPECT_FALSE(xyz.readString(header + "O\t0.0 0.0\t0.0\t0.1 0.2\t0.3\n"
                                       "H 1.0\t0.0 0.5\t0.4\n",
                              truncated));

  XyzFormat control;
  control.setOptions(R"({"perceiveBonds": false})");
  Molecule molecule;
  ASSERT_TRUE(control.readString(header + "O\t0.0 0.0\t0.0\t0.1 0.2\t0.3\n"
                                          "H 1.0\t0.0 0.5\t0.4 0.5\t0.6\n",
                                 molecule))
    << control.error();
  ASSERT_EQ(molecule.atomCount(), 2);
  ASSERT_EQ(molecule.forceVectors().size(), 2);
  EXPECT_EQ(molecule.forceVectors()[0], Vector3(0.1, 0.2, 0.3));
  EXPECT_EQ(molecule.forceVectors()[1], Vector3(0.4, 0.5, 0.6));
}

TEST(XyzTest, write)
{
  XyzFormat xyz;
  Molecule molecule;

  molecule.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  molecule.addAtom(1).setPosition3d(Vector3(0.0, 0.0, 1.089));
  molecule.addAtom(1).setPosition3d(Vector3(1.026719, 0.0, -0.363));
  molecule.addAtom(1).setPosition3d(Vector3(-0.51336, -0.889165, -0.363));
  molecule.addAtom(1).setPosition3d(Vector3(-0.51336, 0.889165, -0.363));
  std::string output;
  EXPECT_EQ(xyz.writeString(output, molecule), true);

  // this part is more of a roundtrip test
  Molecule readMolecule;
  xyz.readString(output, readMolecule);

  // make sure we've got the same thing
  EXPECT_EQ(readMolecule.atomCount(), 5);

  // Bond perception will result in 4 bonds
  EXPECT_EQ(readMolecule.bondCount(), 4);

  EXPECT_EQ(readMolecule.atom(0).atomicNumber(), 6);
  EXPECT_EQ(readMolecule.atom(1).atomicNumber(), 1);
  EXPECT_EQ(readMolecule.atom(2).atomicNumber(), 1);
  EXPECT_EQ(readMolecule.atom(3).atomicNumber(), 1);
  EXPECT_EQ(readMolecule.atom(4).atomicNumber(), 1);

  EXPECT_EQ(readMolecule.atom(4).position3d().x(), -0.51336);
  EXPECT_EQ(readMolecule.atom(4).position3d().y(), 0.889165);
  EXPECT_EQ(readMolecule.atom(4).position3d().z(), -0.36300);
}

TEST(XyzTest, modes)
{
  // This tests some of the mode setting/checking code, not explicitly Xyz but
  // a concrete implementation is required in order to test.
  XyzFormat format;
  format.open(AVOGADRO_DATA "/data/xyz/multi.xyz", FileFormat::Read);
  EXPECT_TRUE(format.isMode(FileFormat::Read));
  EXPECT_TRUE(format.mode() & FileFormat::Read);
  EXPECT_FALSE(format.isMode(FileFormat::Write));

  // Try some combinations now.
  format.open(AVOGADRO_DATA "/data/xyz/multi.xyz",
              FileFormat::Read | FileFormat::MultiMolecule);
  EXPECT_TRUE(format.isMode(FileFormat::Read));
  EXPECT_TRUE(format.isMode(FileFormat::Read | FileFormat::MultiMolecule));
  EXPECT_TRUE(format.isMode(FileFormat::MultiMolecule));
}
