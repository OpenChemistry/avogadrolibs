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
