/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/orca.h>

#include <fstream>
#include <sstream>
#include <string>

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::QuantumIO::ORCAOutput;

// does the basic read work
TEST(OrcaTest, basicRead)
{
  ORCAOutput qcs;
  Molecule molecule;
  EXPECT_TRUE(
    qcs.readFile(AVOGADRO_DATA "/data/orca/formaldehyde.out", molecule));
  ASSERT_EQ(qcs.error(), std::string());

  ASSERT_EQ(molecule.atomCount(), 4);
}

// Regression test: each normal mode holds exactly one displacement per atom.
// The mode arrays were once allocated with resize() *and* push_back(), which
// left every mode with 2N entries whose trailing half was uninitialized.
TEST(OrcaTest, normalModesHaveOneDisplacementPerAtom)
{
  ORCAOutput qcs;
  Molecule molecule;
  ASSERT_TRUE(qcs.readFile(AVOGADRO_DATA "/data/orca/raman.out", molecule));
  ASSERT_EQ(qcs.error(), std::string());

  // Formaldehyde: 4 atoms, so 3N = 12 modes.
  ASSERT_EQ(molecule.atomCount(), 4);
  ASSERT_EQ(molecule.vibrationFrequencies().size(), 12);

  for (size_t mode = 0; mode < molecule.vibrationFrequencies().size(); ++mode)
    EXPECT_EQ(molecule.vibrationLx(mode).size(), molecule.atomCount())
      << "mode " << mode;

  // The C=O stretch is the highest-frequency mode in which the oxygen moves
  // appreciably, and the only one where carbon moves more than hydrogen.
  // Atom order in this file is C, O, H, H.
  auto co = molecule.vibrationLx(9);
  ASSERT_EQ(co.size(), 4);
  EXPECT_NEAR(molecule.vibrationFrequencies()[9], 1866.0, 1.0);
  EXPECT_GT(co[1].norm(), 0.1);          // oxygen genuinely moves
  EXPECT_GT(co[0].norm(), co[2].norm()); // carbon more than hydrogen

  // A C-H stretch leaves the oxygen essentially still.
  auto ch = molecule.vibrationLx(10);
  ASSERT_EQ(ch.size(), 4);
  EXPECT_LT(ch[1].norm(), 0.01);
  EXPECT_GT(ch[2].norm(), 0.5);
}

// Regression test: a file with a trajectory and a Hessian keeps both. The
// vibrations are stored against the conformer they were calculated at.
TEST(OrcaTest, trajectoryAndVibrationsCoexist)
{
  ORCAOutput qcs;
  Molecule molecule;
  ASSERT_TRUE(qcs.readFile(AVOGADRO_DATA "/data/orca/raman.out", molecule));

  EXPECT_GT(molecule.coordinate3dCount(), 1u);
  EXPECT_TRUE(molecule.hasVibrations());
  EXPECT_EQ(molecule.vibrationConformerCount(), 1u);
}

// Regression test: NMR block without atoms should not crash.
TEST(OrcaTest, nmrWithoutAtomsDoesNotCrash)
{
  ORCAOutput qcs;
  Molecule molecule;

  const std::string input = "CHEMICAL SHIELDING SUMMARY (ppm)\n"
                            "header1\n"
                            "header2\n"
                            "header3\n"
                            "header4\n"
                            "1 H 0.772198 0.0\n"
                            "\n";

  EXPECT_FALSE(qcs.readString(input, molecule));
  EXPECT_NE(qcs.error(), std::string());
}

// Regression test: charges block without atoms should not crash.
TEST(OrcaTest, chargesWithoutAtomsDoesNotCrash)
{
  ORCAOutput qcs;
  Molecule molecule;

  const std::string input = "LOEWDIN ATOMIC CHARGES\n"
                            "------------\n"
                            "0 C :   -0.228326\n"
                            "\n";

  EXPECT_FALSE(qcs.readString(input, molecule));
  EXPECT_NE(qcs.error(), std::string());
}

// Regression test: malformed bond order line should not crash.
TEST(OrcaTest, bondOrdersMalformedLineDoesNotCrash)
{
  ORCAOutput qcs;
  Molecule molecule;

  const std::string input = "Mayer bond orders larger than 0.100000\n"
                            "B(  3-T available\n"
                            "\n";

  EXPECT_FALSE(qcs.readString(input, molecule));
  EXPECT_NE(qcs.error(), std::string());
}
