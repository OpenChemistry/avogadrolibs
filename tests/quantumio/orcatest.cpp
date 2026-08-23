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
// vibrations are stored against the conformer they were calculated at, and
// the molecule opens on the final geometry.
TEST(OrcaTest, trajectoryAndVibrationsCoexist)
{
  ORCAOutput qcs;
  Molecule molecule;
  ASSERT_TRUE(qcs.readFile(AVOGADRO_DATA "/data/orca/raman.out", molecule));

  ASSERT_GT(molecule.coordinate3dCount(), 1u);
  EXPECT_EQ(molecule.coordinate3d(),
            static_cast<int>(molecule.coordinate3dCount()) - 1);
  EXPECT_TRUE(molecule.hasVibrations());
  EXPECT_EQ(molecule.vibrationConformerCount(), 1u);
}

// A transition state search recomputes the Hessian every few optimization
// cycles, so one file carries several complete sets of modes, each belonging
// to the geometry it was computed at. Before per-conformer storage these ran
// together into a single list of 3N x (number of Hessians) bogus modes.
TEST(OrcaTest, transitionStateKeepsEveryHessianWithItsGeometry)
{
  ORCAOutput qcs;
  Molecule molecule;
  ASSERT_TRUE(qcs.readFile(AVOGADRO_DATA "/data/orca/caffeine.out", molecule));
  ASSERT_EQ(qcs.error(), std::string());

  ASSERT_EQ(molecule.atomCount(), 24);
  ASSERT_EQ(molecule.coordinate3dCount(), 46u);

  // The Hessian is recomputed every five cycles starting at the first, and
  // once more at the converged geometry (the last conformer).
  const size_t expected[] = { 0, 5, 10, 15, 20, 25, 30, 35, 40, 45 };
  const size_t expectedCount = sizeof(expected) / sizeof(expected[0]);
  EXPECT_EQ(molecule.vibrationConformerCount(), expectedCount);
  ASSERT_EQ(molecule.vibrationConformers().size(), expectedCount);
  for (size_t i = 0; i < expectedCount; ++i)
    EXPECT_EQ(molecule.vibrationConformers()[i], expected[i]) << "entry " << i;

  // Every set is one complete Hessian for this molecule: 3N modes, each with
  // one displacement per atom, and a matching IR intensity.
  for (size_t conformer : molecule.vibrationConformers()) {
    EXPECT_EQ(molecule.vibrationFrequencies(conformer).size(), 72u)
      << "conformer " << conformer;
    EXPECT_EQ(molecule.vibrationIRIntensities(conformer).size(), 72u)
      << "conformer " << conformer;
    for (int mode = 0; mode < 72; ++mode)
      ASSERT_EQ(molecule.vibrationLx(mode, conformer).size(), 24u)
        << "conformer " << conformer << " mode " << mode;
  }

  // The sets are distinct geometries, so they carry distinct modes. The
  // search starts well away from the saddle point and ends on a first-order
  // transition state: exactly one imaginary frequency.
  auto imaginaryCount = [&](size_t conformer) {
    auto frequencies = molecule.vibrationFrequencies(conformer);
    int count = 0;
    for (size_t i = 0; i < frequencies.size(); ++i)
      if (frequencies[i] < -1.0)
        ++count;
    return count;
  };
  EXPECT_EQ(imaginaryCount(0), 2);
  EXPECT_EQ(imaginaryCount(40), 1);
  EXPECT_NEAR(molecule.vibrationFrequencies(0)[6], -132.3, 0.5);
  EXPECT_NEAR(molecule.vibrationFrequencies(40)[6], -68.9, 0.5);
}

// The molecule opens on the converged geometry, and for a completed run that
// geometry carries its own Hessian - the modes a user wants to see first.
TEST(OrcaTest, convergedGeometryCarriesItsOwnHessian)
{
  ORCAOutput qcs;
  Molecule molecule;
  ASSERT_TRUE(qcs.readFile(AVOGADRO_DATA "/data/orca/caffeine.out", molecule));

  const size_t finalConformer = molecule.coordinate3dCount() - 1;
  EXPECT_EQ(molecule.coordinate3d(), static_cast<int>(finalConformer));
  ASSERT_TRUE(molecule.hasVibrations());
  EXPECT_EQ(molecule.vibrationFrequencies().size(), 72u);

  // A converged transition state has exactly one imaginary frequency.
  auto frequencies = molecule.vibrationFrequencies();
  int imaginary = 0;
  for (size_t i = 0; i < frequencies.size(); ++i)
    if (frequencies[i] < -1.0)
      ++imaginary;
  EXPECT_EQ(imaginary, 1);
  EXPECT_NEAR(frequencies[6], -31.0, 0.5);
}

// A job that dies part way through a Hessian leaves a set with frequencies
// but no normal modes. That partial set must be dropped rather than handed to
// the molecule, and must not disturb the sets that did complete.
TEST(OrcaTest, truncatedHessianIsDroppedNotStored)
{
  std::ifstream file(AVOGADRO_DATA "/data/orca/caffeine.out");
  ASSERT_TRUE(file.is_open());
  std::stringstream buffer;
  buffer << file.rdbuf();
  std::string contents = buffer.str();

  // Cut shortly after the last frequency block starts, so its frequencies are
  // partly present but its NORMAL MODES block never arrives.
  const std::string header = "VIBRATIONAL FREQUENCIES";
  const size_t lastBlock = contents.rfind(header);
  ASSERT_NE(lastBlock, std::string::npos);
  contents.resize(lastBlock + 2000);

  ORCAOutput qcs;
  Molecule molecule;
  ASSERT_TRUE(qcs.readString(contents, molecule));

  // The nine complete Hessians survive; the truncated tenth is gone.
  EXPECT_EQ(molecule.vibrationConformerCount(), 9u);
  EXPECT_FALSE(molecule.hasVibrations(45));
  EXPECT_TRUE(molecule.hasVibrations(40));
  EXPECT_EQ(molecule.vibrationFrequencies(40).size(), 72u);
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
