/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/nwchemlog.h>

#include <fstream>
#include <sstream>
#include <string>

using Avogadro::Core::Molecule;
using Avogadro::QuantumIO::NWChemLog;

namespace {

std::string readFixture(const std::string& path)
{
  std::ifstream file(path);
  if (!file.is_open())
    return std::string();
  std::stringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

// A minimal geometry section, laid out as readAtoms expects it.
const std::string geometryBlock =
  " Output coordinates in angstroms (scale by  1.889725989 to convert to "
  "a.u.)\n"
  "\n"
  "  No.       Tag          Charge          X              Y              Z\n"
  " ---- ---------------- ---------- -------------- -------------- "
  "--------------\n"
  "    1 o                    8.0000     0.00000000     0.00000000    "
  "-0.30459770\n"
  "    2 mg                  12.0000     0.00000000     1.75000000    "
  "-0.30459770\n"
  "\n";

} // namespace

// NWChem prints the modes of one Hessian in column blocks, so the frequency
// arrays have to accumulate across several P.Frequency sections. Biphenyl is
// large enough to need eleven of them for its 3N modes.
TEST(NWChemLogTest, oneHessianIsAssembledFromItsColumnBlocks)
{
  NWChemLog reader;
  Molecule molecule;
  ASSERT_TRUE(
    reader.readFile(AVOGADRO_DATA "/data/nwchem/hess_biph.out", molecule));
  ASSERT_EQ(reader.error(), std::string());

  ASSERT_EQ(molecule.atomCount(), 22);
  EXPECT_EQ(molecule.vibrationFrequencies().size(), 3 * molecule.atomCount());
  EXPECT_EQ(molecule.vibrationConformerCount(), 1u);
  for (size_t mode = 0; mode < molecule.vibrationFrequencies().size(); ++mode)
    ASSERT_EQ(molecule.vibrationLx(static_cast<int>(mode)).size(),
              molecule.atomCount())
      << "mode " << mode;
}

// The geometries of an optimization are kept as conformers rather than each
// one replacing the last, so the path taken is still available.
TEST(NWChemLogTest, geometriesAreKeptAsConformers)
{
  NWChemLog reader;
  Molecule molecule;
  ASSERT_TRUE(
    reader.readFile(AVOGADRO_DATA "/data/nwchem/hess_actlist.out", molecule));

  ASSERT_EQ(molecule.atomCount(), 2);
  EXPECT_EQ(molecule.coordinate3dCount(), 2u);
  // The molecule opens on the last geometry, which is the one the Hessian
  // was computed at.
  EXPECT_EQ(molecule.coordinate3d(), 1);
  EXPECT_TRUE(molecule.hasVibrations());
  EXPECT_EQ(molecule.vibrationFrequencies().size(), 3 * molecule.atomCount());
}

// Regression test: two Hessians in one file must not run together. The
// accumulators cannot simply be reset per P.Frequency block - that would
// break the column-block assembly above - so they are banked when a new
// geometry arrives. Before this, a two atom molecule reported twice the
// modes it has.
TEST(NWChemLogTest, separateHessiansDoNotAccumulate)
{
  const std::string one =
    readFixture(AVOGADRO_DATA "/data/nwchem/hess_actlist.out");
  ASSERT_FALSE(one.empty());

  NWChemLog reader;
  Molecule molecule;
  ASSERT_TRUE(reader.readString(one + one, molecule));

  ASSERT_EQ(molecule.atomCount(), 2);
  const size_t expectedModes = 3 * molecule.atomCount();

  // Each Hessian keeps its own modes, against its own geometry.
  EXPECT_EQ(molecule.vibrationConformerCount(), 2u);
  for (size_t conformer : molecule.vibrationConformers()) {
    EXPECT_EQ(molecule.vibrationFrequencies(conformer).size(), expectedModes)
      << "conformer " << conformer;
    EXPECT_EQ(molecule.vibrationIRIntensities(conformer).size(), expectedModes)
      << "conformer " << conformer;
  }

  // And the active conformer shows one Hessian, not both concatenated.
  EXPECT_EQ(molecule.vibrationFrequencies().size(), expectedModes);
}

// Regression tests for GitHub issue #3104: the normal mode block of a
// P.Frequency section used to be indexed by whatever each row happened to
// contain, reading and writing out of bounds on malformed output.

// The 20 byte input found by fuzzing. There is no geometry, so nothing can
// be read, but it must not crash.
TEST(NWChemLogTest, truncatedFrequencyBlockDoesNotOverrun)
{
  const char buf[] = "P.Frequency 9\n\n\0 1\n ";
  const std::string input(buf, 20);
  NWChemLog reader;
  Molecule molecule;
  reader.readString(input, molecule);
  EXPECT_EQ(molecule.atomCount(), 0);
  EXPECT_FALSE(molecule.hasVibrations());
}

// A later row with more values than the first used to write past the end
// of the column storage.
TEST(NWChemLogTest, wideFrequencyRowEndsTheBlock)
{
  const std::string input = geometryBlock +
                            " P.Frequency        1.00        2.00\n"
                            "\n"
                            "           1     0.1     0.2\n"
                            "           2     0.1     0.2\n"
                            "           3     0.1     0.2     0.3     0.4\n"
                            "\n";
  NWChemLog reader;
  Molecule molecule;
  reader.readString(input, molecule);
  EXPECT_EQ(molecule.atomCount(), 2);
  // The wide row ends the block after two rows, which is not a whole number
  // of atoms, so no modes are recorded.
  EXPECT_FALSE(molecule.hasVibrations());
  EXPECT_FALSE(reader.error().empty());
}

// More frequencies than columns of data used to index past the columns.
TEST(NWChemLogTest, fewerColumnsThanFrequencies)
{
  const std::string input = geometryBlock +
                            " P.Frequency        1.00        2.00        3.00\n"
                            "\n"
                            "           1     0.1\n"
                            "           2     0.2\n"
                            "           3     0.3\n"
                            "\n";
  NWChemLog reader;
  Molecule molecule;
  reader.readString(input, molecule);
  EXPECT_EQ(molecule.atomCount(), 2);
  EXPECT_FALSE(molecule.hasVibrations());
}

// A column that is not a multiple of three used to read past its end when
// the components were gathered into vectors.
TEST(NWChemLogTest, rowCountMustBeMultipleOfThree)
{
  const std::string input = geometryBlock +
                            " P.Frequency        1.00        2.00\n"
                            "\n"
                            "           1     0.1     0.2\n"
                            "           2     0.1     0.2\n"
                            "           3     0.1     0.2\n"
                            "           4     0.1     0.2\n"
                            "\n";
  NWChemLog reader;
  Molecule molecule;
  reader.readString(input, molecule);
  EXPECT_FALSE(molecule.hasVibrations());
  EXPECT_NE(reader.error().find("not a multiple of 3"), std::string::npos);
}

// A bad token in the middle of the frequencies is an error, not silently
// accepted because the last one parsed.
TEST(NWChemLogTest, badFrequencyTokenIsReported)
{
  const std::string input = geometryBlock +
                            " P.Frequency        1.00        abc        3.00\n"
                            "\n"
                            "           1     0.1     0.2     0.3\n"
                            "\n";
  NWChemLog reader;
  Molecule molecule;
  reader.readString(input, molecule);
  EXPECT_FALSE(molecule.hasVibrations());
  EXPECT_NE(reader.error().find("Error reading frequencies"),
            std::string::npos);
}
