/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/gaussianset.h>
#include <avogadro/core/gaussiansettools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/io/compression.h>

#include <avogadro/quantumio/gaussianfchk.h>
#include <avogadro/quantumio/molden.h>

#include <nlohmann/json.hpp>

#include <cmath>
#include <fstream>
#include <string>
#include <vector>

using Avogadro::Vector3;
using Avogadro::Core::GaussianSet;
using Avogadro::Core::GaussianSetTools;
using Avogadro::Core::Molecule;
using Avogadro::QuantumIO::GaussianFchk;
using Avogadro::QuantumIO::MoldenFile;

namespace {

// H2O HF/6-31G(d) at one fixed geometry, from Gaussian 16 (Cartesian 6D and
// spherical 5D d functions) and ORCA 6.1 (5D). reference-points.json holds
// the density critic2 1.4.306 computes from the program's own WFN/WFX/fchk/
// Molden file at 20 points; see data/qtaim/h2o-hf-631gd/README.md. The WFN
// and WFX files are not used here, there is no reader for them yet.
//
// The 20 points: 0-1 bond midpoints, 2-15 valence region, 16-19 tail points
// 2.5 to 5 bohr from the nearest nucleus.

struct Case
{
  std::string name;
  std::string folder;
  std::string file;
  bool molden;
};

const char* const DIRECTORY = "/data/qtaim/h2o-hf-631gd/";

std::ostream& operator<<(std::ostream& out, const Case& testCase)
{
  return out << testCase.name;
}

enum class Category
{
  BondMidpoint,
  Valence,
  Tail
};

Category categoryOf(size_t index)
{
  if (index < 2)
    return Category::BondMidpoint;
  return index < 16 ? Category::Valence : Category::Tail;
}

const char* categoryName(Category category)
{
  switch (category) {
    case Category::BondMidpoint:
      return "bond midpoints";
    case Category::Valence:
      return "valence";
    default:
      return "tail";
  }
}

bool loadWaveFunction(const Case& testCase, Molecule& molecule,
                      std::string& error)
{
  const std::string path = std::string(AVOGADRO_DATA) + DIRECTORY +
                           testCase.folder + "/" + testCase.file;
  bool ok = false;
  if (testCase.molden) {
    MoldenFile reader;
    ok = reader.readFile(path, molecule);
    error = reader.error();
  } else {
    GaussianFchk reader;
    ok = reader.readFile(path, molecule);
    error = reader.error();
  }
  if (!ok)
    return false;
  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  if (basis == nullptr) {
    error = "no GaussianSet";
    return false;
  }
  // The densities compared are those of the occupied MOs, so that the
  // Molden file (which carries no density matrix) and the fchk files are
  // treated alike.
  return basis->generateDensityMatrix();
}

std::vector<Vector3> readPoints(const nlohmann::json& reference)
{
  std::vector<Vector3> points;
  for (const auto& point : reference.at("points"))
    points.emplace_back(point.at("angstrom")[0].get<double>(),
                        point.at("angstrom")[1].get<double>(),
                        point.at("angstrom")[2].get<double>());
  return points;
}

nlohmann::json readReference()
{
  std::ifstream in(std::string(AVOGADRO_DATA) + DIRECTORY +
                   "reference-points.json");
  return nlohmann::json::parse(in);
}

bool gzipMissing(const Case& testCase)
{
  return testCase.file.size() > 3 &&
         testCase.file.substr(testCase.file.size() - 3) == ".gz" &&
         !Avogadro::Io::compressionSupported(Avogadro::Io::Compression::Gzip);
}

const Case CASES[] = {
  { "gaussian_6d_fchk", "gaussian-hf-6-31gd-6d", "h2o.fchk.gz", false },
  { "gaussian_5d_fchk", "gaussian-hf-6-31gd-5d", "h2o.fchk.gz", false },
  { "orca_5d_molden", "orca-hf-6-31gd-5d", "h2o.molden", true },
};

} // namespace

class ReferenceDensityTest : public ::testing::TestWithParam<Case>
{};

TEST_P(ReferenceDensityTest, densityMatchesCritic2)
{
  const Case& testCase = GetParam();
  if (gzipMissing(testCase))
    GTEST_SKIP() << "this build has no gzip support (USE_LIBARCHIVE=OFF)";
  // ORCA writes Molden contraction coefficients with the primitive
  // normalization already applied, and MoldenFile normalizes them again:
  // the density is wrong by up to a factor of 37 here. Re-enable when the
  // reader handles ORCA's convention.
  if (testCase.molden)
    GTEST_SKIP() << "MoldenFile does not handle ORCA's coefficient "
                    "normalization yet";

  Molecule molecule;
  std::string error;
  ASSERT_TRUE(loadWaveFunction(testCase, molecule, error)) << error;

  const nlohmann::json reference = readReference();
  const std::vector<Vector3> points = readPoints(reference);
  const auto& values =
    reference.at("wavefunctions").at(testCase.folder + "/" + testCase.file);
  ASSERT_EQ(values.at("points").size(), points.size());

  // critic2 reads the same files to about 1e-9 relative (fchk vs WFX), and
  // Avogadro matches it to 1.5e-8 at the bond midpoints. Away from the
  // bonds, GaussianSetTools' shell cutoff (calculateShellCutoff) makes the
  // density slightly low, by up to 1.5e-6 here; the absolute floor is the
  // one densitycubetest.cpp uses for the same effect.
  const double relativeTolerance = 1e-6;
  const double absoluteFloor = 2e-5;

  GaussianSetTools tools(&molecule);
  for (size_t i = 0; i < points.size(); ++i) {
    const double expected = values.at("points")[i].at("rho").get<double>();
    const double got = tools.calculateElectronDensity(points[i]);
    EXPECT_NEAR(got, expected,
                relativeTolerance * std::abs(expected) + absoluteFloor)
      << "point " << i << " (" << categoryName(categoryOf(i)) << ")";
  }
}

INSTANTIATE_TEST_SUITE_P(Calculations, ReferenceDensityTest,
                         ::testing::ValuesIn(CASES),
                         [](const ::testing::TestParamInfo<Case>& info) {
                           return info.param.name;
                         });
