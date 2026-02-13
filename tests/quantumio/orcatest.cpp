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
