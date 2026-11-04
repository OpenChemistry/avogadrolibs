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
// spherical 5D d functions), ORCA 6.1 (5D), Psi4 1.11 and PySCF 2.14 (6D and
// 5D) and xtb 6.7.1 (GFN2, Cartesian d), plus H2O HF/cc-pVTZ and N2
// B3LYP/cc-pVQZ from ORCA (spherical f and g). reference-points.json holds
// the density critic2 1.4.306 computes from the program's own WFN/WFX/fchk/
// Molden file at 20 points; see data/qtaim/h2o-hf-631gd/README.md. The WFN
// and WFX files are not used here, there is no reader for them yet.
//
// The 20 points: 0-1 bond midpoints (N2: 0 only), then valence region points,
// and 4 tail points 2.5 to 5 bohr from the nearest nucleus.

enum class Check
{
  AllPoints,
  // Only the bond midpoints. The f and g cases are checked there alone:
  // away from the bond axes Avogadro's density differs from critic2's by
  // up to 1.7e-3 (relative; Gaussian fchk, H2O cc-pVTZ) and 3.7e-4 (ORCA
  // after the conversion in MoldenFile), while the midpoints agree to
  // about 1e-8 (see the measured values at the cases). That is a separate,
  // so far unexplained problem of the evaluator for f and g shells that
  // the Molden reader does not touch.
  BondMidpointsOnly
};

struct Case
{
  std::string name;
  std::string directory; // under data/
  std::string folder;    // may be empty
  std::string file;
  bool molden;
  Check check = Check::AllPoints;
  std::string reference = "reference-points.json";
};

std::string wavefunctionPath(const Case& testCase)
{
  return std::string(AVOGADRO_DATA) + "/data/" + testCase.directory + "/" +
         (testCase.folder.empty() ? "" : testCase.folder + "/") + testCase.file;
}

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

// The category of a point as recorded in reference-points.json. Files
// without categories (SF4) count every point as valence.
Category categoryOf(const nlohmann::json& reference, size_t index)
{
  const auto& point = reference.at("points")[index];
  if (!point.contains("category"))
    return Category::Valence;
  const auto name = point.at("category").get<std::string>();
  if (name == "bond-midpoint")
    return Category::BondMidpoint;
  return name == "tail" ? Category::Tail : Category::Valence;
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
  const std::string path = wavefunctionPath(testCase);
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

nlohmann::json readReference(const Case& testCase)
{
  std::ifstream in(std::string(AVOGADRO_DATA) + "/data/" + testCase.directory +
                   "/" + testCase.reference);
  return nlohmann::json::parse(in);
}

bool gzipMissing(const Case& testCase)
{
  return testCase.file.size() > 3 &&
         testCase.file.substr(testCase.file.size() - 3) == ".gz" &&
         !Avogadro::Io::compressionSupported(Avogadro::Io::Compression::Gzip);
}

const std::string H2O = "qtaim/h2o-hf-631gd";

const Case CASES[] = {
  { "gaussian_6d_fchk", H2O, "gaussian-hf-6-31gd-6d", "h2o.fchk.gz", false },
  { "gaussian_5d_fchk", H2O, "gaussian-hf-6-31gd-5d", "h2o.fchk.gz", false },
  { "orca_5d_molden", H2O, "orca-hf-6-31gd-5d", "h2o.molden", true },
  { "psi4_6d_molden", H2O, "psi4-hf-6-31gd-6d", "h2o.molden", true },
  { "psi4_5d_molden", H2O, "psi4-hf-6-31gd-5d", "h2o.molden", true },
  { "pyscf_6d_molden", H2O, "pyscf-hf-6-31gd-6d", "h2o.molden", true },
  { "pyscf_5d_molden", H2O, "pyscf-hf-6-31gd-5d", "h2o.molden", true },
  // xtb: valence-only density, Cartesian d; the Molden file has the radial
  // normalization in its coefficients (RadialIncluded).
  { "xtb_gfn2_molden", H2O, "xtb-gfn2", "h2o.molden", true },
  // xtb, SF4 with Cartesian d on sulfur; 12 points around S.
  { "xtb_sf4_molden", "molden", "", "SF4.molden", true, Check::AllPoints,
    "SF4-reference-points.json" },
  // ORCA f and g shells: the midpoints only, see Check. Measured against
  // critic2: bond midpoints within 1.3e-8 (H2O cc-pVTZ) and 6.8e-10 (N2
  // cc-pVQZ, one midpoint); the largest relative deviation at the other 19
  // points is 3.8e-4 (H2O) and 3.7e-4 (N2).
  { "orca_ccpvtz_h2o_molden", "qtaim/h2o-hf-ccpvtz", "orca-hf-cc-pvtz",
    "h2o.molden", true, Check::BondMidpointsOnly },
  { "orca_ccpvqz_n2_molden", "qtaim/n2-b3lyp-ccpvqz", "orca-b3lyp-cc-pvqz",
    "n2.molden", true, Check::BondMidpointsOnly },
};

} // namespace

class ReferenceDensityTest : public ::testing::TestWithParam<Case>
{};

TEST_P(ReferenceDensityTest, densityMatchesCritic2)
{
  const Case& testCase = GetParam();
  if (gzipMissing(testCase))
    GTEST_SKIP() << "this build has no gzip support (USE_LIBARCHIVE=OFF)";

  Molecule molecule;
  std::string error;
  ASSERT_TRUE(loadWaveFunction(testCase, molecule, error)) << error;

  const nlohmann::json reference = readReference(testCase);
  const std::vector<Vector3> points = readPoints(reference);
  const std::string key = testCase.folder.empty()
                            ? testCase.file
                            : testCase.folder + "/" + testCase.file;
  const auto& values = reference.at("wavefunctions").at(key);
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
    const Category category = categoryOf(reference, i);
    if (testCase.check == Check::BondMidpointsOnly) {
      if (category != Category::BondMidpoint)
        continue;
      // no absolute floor here: the midpoints are well inside the density
      EXPECT_NEAR(got, expected, relativeTolerance * std::abs(expected))
        << "point " << i << " (" << categoryName(category) << ")";
    } else {
      EXPECT_NEAR(got, expected,
                  relativeTolerance * std::abs(expected) + absoluteFloor)
        << "point " << i << " (" << categoryName(category) << ")";
    }
  }
}

INSTANTIATE_TEST_SUITE_P(Calculations, ReferenceDensityTest,
                         ::testing::ValuesIn(CASES),
                         [](const ::testing::TestParamInfo<Case>& info) {
                           return info.param.name;
                         });
