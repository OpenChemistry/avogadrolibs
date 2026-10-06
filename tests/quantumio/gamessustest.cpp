/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/gaussianset.h>
#include <avogadro/core/molecule.h>

#include <avogadro/quantumio/gamessus.h>

#include <string>

using Avogadro::Core::GaussianSet;
using Avogadro::Core::Molecule;
using Avogadro::QuantumIO::GAMESSUSOutput;

namespace {

const std::string kCoordinates =
  " ATOM      ATOMIC                      COORDINATES (BOHR)\n"
  "           CHARGE         X                   Y                   Z\n"
  " C           6.0     0.0000000000        0.0000000000        0.0000000000\n"
  "\n";

const std::string kBasisHeader =
  "     ATOMIC BASIS SET\n"
  "     ----------------\n"
  "  SHELL TYPE  PRIMITIVE        EXPONENT          CONTRACTION "
  "COEFFICIENT(S)\n"
  "\n";

const std::string kBasisEnd =
  "\n TOTAL NUMBER OF BASIS SET SHELLS             =    1\n";

// The block header for two MOs, followed by the given coefficient rows.
std::string eigenvectors(const std::string& rows)
{
  return "          ------------\n"
         "          EIGENVECTORS\n"
         "          ------------\n"
         "\n"
         "                      1          2\n"
         "                   -2.3155    -0.7371\n"
         "                     A          A\n" +
         rows + " ...... END OF RHF CALCULATION ......\n";
}

// Fails, and through the parser's own error rather than an exception caught
// by FileFormat's guard (which fuzz builds compile out).
::testing::AssertionResult readFailsCleanly(const std::string& input)
{
  GAMESSUSOutput format;
  Molecule molecule;
  if (format.readString(input, molecule))
    return ::testing::AssertionFailure() << "read succeeded";
  if (format.error().find("appears to be malformed") != std::string::npos)
    return ::testing::AssertionFailure()
           << "read threw an exception: " << format.error();
  return ::testing::AssertionSuccess();
}

} // namespace

// Real output files still read, with every shell and MO.
TEST(GAMESSUSTest, readDataFiles)
{
  {
    GAMESSUSOutput format;
    Molecule molecule;
    ASSERT_TRUE(
      format.readFile(AVOGADRO_DATA "/data/gamess/d-only.gamess", molecule));
    EXPECT_EQ(molecule.atomCount(), 5);
    auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
    ASSERT_NE(basis, nullptr);
    EXPECT_EQ(basis->symmetry().size(), 21);
  }
  {
    GAMESSUSOutput format;
    Molecule molecule;
    ASSERT_TRUE(
      format.readFile(AVOGADRO_DATA "/data/gamess/f-only.gamess", molecule));
    EXPECT_EQ(molecule.atomCount(), 5);
    auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
    ASSERT_NE(basis, nullptr);
    EXPECT_EQ(basis->symmetry().size(), 21);
  }
}

// An L (SP) shell has a P coefficient in a sixth column. A row without it
// left fewer P coefficients than primitives, and loading the basis read
// past the end of them.
TEST(GAMESSUSTest, spShellMissingPCoefficientFails)
{
  const std::string complete =
    "      1   L       1             2.9412494   -0.099967229187    "
    "0.155916274999\n"
    "      1   L       2             0.6834831    0.399512826089    "
    "0.607683718598\n";
  const std::string missing =
    "      1   L       1             2.9412494   -0.099967229187    "
    "0.155916274999\n"
    "      1   L       2             0.6834831    0.399512826089\n";

  EXPECT_TRUE(readFailsCleanly(kCoordinates + kBasisHeader + " C\n\n" +
                               missing + kBasisEnd));

  // Sanity check: with both columns the shell loads as S plus P.
  GAMESSUSOutput format;
  Molecule molecule;
  ASSERT_TRUE(format.readString(
    kCoordinates + kBasisHeader + " C\n\n" + complete + kBasisEnd, molecule));
  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);
  ASSERT_EQ(basis->symmetry().size(), 2);
  EXPECT_EQ(basis->symmetry()[0], GaussianSet::S);
  EXPECT_EQ(basis->symmetry()[1], GaussianSet::P);
  EXPECT_EQ(basis->atomIndices()[0], 0);
  EXPECT_EQ(basis->atomIndices()[1], 0);
}

// Basis shells must belong to an atom that was read.
TEST(GAMESSUSTest, shellAtomOutOfRangeFails)
{
  const std::string shell =
    "      1   S       1             2.9412494    1.000000000000\n";

  // A shell before any atom label.
  EXPECT_TRUE(
    readFailsCleanly(kCoordinates + kBasisHeader + shell + "\n" + kBasisEnd));
  // A shell on a second atom when the coordinates gave only one.
  EXPECT_TRUE(readFailsCleanly(kCoordinates + kBasisHeader + " C\n\n" + shell +
                               "\n H\n\n" + shell + kBasisEnd));
  // A basis set with no coordinates at all.
  EXPECT_TRUE(readFailsCleanly(kBasisHeader + " C\n\n" + shell + kBasisEnd));
}

// F functions are reordered in place, ten coefficients per MO. Eigenvectors
// cut short of that were read past their end.
TEST(GAMESSUSTest, truncatedEigenvectorsWithFShellFails)
{
  const std::string fShell =
    "      1   F       1             0.8000000    1.000000000000\n";
  EXPECT_TRUE(readFailsCleanly(
    kCoordinates + kBasisHeader + " C\n\n" + fShell + kBasisEnd +
    eigenvectors("    1  C  1 XXX  -0.000072   0.000000\n"
                 "    2  C  1 YYY   0.000036   0.000000\n")));
}

// A coefficient row wider than the block's first row has more columns than
// there are MOs in the block.
TEST(GAMESSUSTest, eigenvectorRowWiderThanBlockFails)
{
  const std::string sShell =
    "      1   S       1             2.9412494    1.000000000000\n";
  EXPECT_TRUE(readFailsCleanly(
    kCoordinates + kBasisHeader + " C\n\n" + sShell + kBasisEnd +
    eigenvectors("    1  C  1 S    -0.000072   0.000000\n"
                 "    2  C  1 S     0.000036   0.000000   0.1   0.2\n")));
}
