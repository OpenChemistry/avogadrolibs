/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/gaussiansettools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/gaussianfchk.h>

#include <avogadro/core/avogadrocore.h>

#include <cmath>
#include <string>
#include <vector>

using Avogadro::Vector3;
using Avogadro::Core::BasisSet;
using Avogadro::Core::Cube;
using Avogadro::Core::GaussianSet;
using Avogadro::Core::GaussianSetTools;
using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::QuantumIO::GaussianFchk;

namespace {

// Helper: load a molecule from an fchk file and verify the basis set is valid.
bool loadFchk(const std::string& path, Molecule& molecule)
{
  GaussianFchk format;
  if (!format.readFile(path, molecule))
    return false;
  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  if (!basis)
    return false;
  basis->initCalculation();
  return true;
}

// Helper: generate a set of test points around and near a molecule.
// Returns points at atom centers, near atoms, along bonds, and in the
// diffuse region far from the molecule.
std::vector<Vector3> generateTestPoints(const Molecule& molecule)
{
  std::vector<Vector3> points;

  // At each atom center (should have large basis function values)
  for (Avogadro::Index i = 0; i < molecule.atomCount(); ++i) {
    Vector3 pos = molecule.atomPosition3d(i);
    points.push_back(pos);
  }

  // Slightly offset from each atom (0.1 Angstrom in each direction)
  for (Avogadro::Index i = 0; i < molecule.atomCount(); ++i) {
    Vector3 pos = molecule.atomPosition3d(i);
    points.push_back(pos + Vector3(0.1, 0.0, 0.0));
    points.push_back(pos + Vector3(0.0, 0.1, 0.0));
    points.push_back(pos + Vector3(0.0, 0.0, 0.1));
  }

  // Bond midpoints (between first atom and all others, if more than one atom)
  if (molecule.atomCount() > 1) {
    Vector3 p0 = molecule.atomPosition3d(0);
    for (Avogadro::Index i = 1; i < molecule.atomCount(); ++i) {
      Vector3 pi = molecule.atomPosition3d(i);
      points.push_back(0.5 * (p0 + pi));
    }
  }

  // Far-field points (3-5 Angstroms away from origin — diffuse region)
  points.push_back(Vector3(3.0, 0.0, 0.0));
  points.push_back(Vector3(0.0, 3.0, 0.0));
  points.push_back(Vector3(0.0, 0.0, 3.0));
  points.push_back(Vector3(5.0, 5.0, 5.0));

  // Origin
  points.push_back(Vector3(0.0, 0.0, 0.0));

  return points;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Basic validity tests
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, isValid)
{
  Molecule molecule;
  ASSERT_TRUE(
    loadFchk(AVOGADRO_DATA "/data/fchk/h2o-restricted.fchk", molecule));

  GaussianSetTools tools(&molecule);
  EXPECT_TRUE(tools.isValid());
}

TEST(GaussianSetToolsTest, isValidNullMolecule)
{
  GaussianSetTools tools(nullptr);
  EXPECT_FALSE(tools.isValid());
}

// ---------------------------------------------------------------------------
// Water (RHF, STO-3G): S and SP shells only
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, waterMolecularOrbital)
{
  Molecule molecule;
  ASSERT_TRUE(
    loadFchk(AVOGADRO_DATA "/data/fchk/h2o-restricted.fchk", molecule));

  GaussianSetTools tools(&molecule);
  auto points = generateTestPoints(molecule);

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);
  unsigned int nMOs = basis->molecularOrbitalCount();
  ASSERT_GT(nMOs, 0u);

  // Evaluate the HOMO (highest occupied MO)
  // For STO-3G water: 5 electrons each spin → MO index 4 (0-based) is HOMO
  int homo = static_cast<int>(basis->electronCount(BasisSet::Paired)) / 2 - 1;
  ASSERT_GE(homo, 0);

  // The first MO (1s-like) should always be large at the heavy atom center
  double mo0AtO =
    tools.calculateMolecularOrbital(molecule.atomPosition3d(0), 0);
  double farAway =
    tools.calculateMolecularOrbital(Vector3(10.0, 10.0, 10.0), 0);

  EXPECT_GT(std::abs(mo0AtO), 1e-2)
    << "First MO at oxygen should be non-trivial";
  EXPECT_LT(std::abs(farAway), 1e-6)
    << "MO value far from molecule should be near zero";

  // The HOMO may have a node at the nucleus, so test slightly offset
  double homoOffset = tools.calculateMolecularOrbital(
    molecule.atomPosition3d(0) + Vector3(0.2, 0.2, 0.0), homo);
  EXPECT_GT(std::abs(homoOffset), 1e-4)
    << "HOMO should be non-trivial near (not exactly at) oxygen";

  // Evaluate all test points — just verify no crashes or NaN
  for (const auto& pt : points) {
    double val = tools.calculateMolecularOrbital(pt, homo);
    EXPECT_FALSE(std::isnan(val)) << "NaN at point " << pt.transpose();
    EXPECT_FALSE(std::isinf(val)) << "Inf at point " << pt.transpose();
  }
}

TEST(GaussianSetToolsTest, waterElectronDensity)
{
  Molecule molecule;
  ASSERT_TRUE(
    loadFchk(AVOGADRO_DATA "/data/fchk/h2o-restricted.fchk", molecule));

  GaussianSetTools tools(&molecule);
  auto points = generateTestPoints(molecule);

  // Electron density must be non-negative everywhere
  for (const auto& pt : points) {
    double rho = tools.calculateElectronDensity(pt);
    EXPECT_GE(rho, 0.0) << "Density must be >= 0 at " << pt.transpose();
    EXPECT_FALSE(std::isnan(rho)) << "NaN at " << pt.transpose();
  }

  // Density at oxygen should be larger than far away
  double rhoAtO = tools.calculateElectronDensity(molecule.atomPosition3d(0));
  double rhoFar = tools.calculateElectronDensity(Vector3(10.0, 10.0, 10.0));
  EXPECT_GT(rhoAtO, 1e-2) << "Density at oxygen should be significant";
  EXPECT_LT(rhoFar, 1e-6) << "Density far away should be negligible";

  // Density at oxygen should be larger than at hydrogen
  double rhoAtH = tools.calculateElectronDensity(molecule.atomPosition3d(1));
  EXPECT_GT(rhoAtO, rhoAtH)
    << "Density at oxygen should exceed density at hydrogen";
}

TEST(GaussianSetToolsTest, waterCubeConsistency)
{
  Molecule molecule;
  ASSERT_TRUE(
    loadFchk(AVOGADRO_DATA "/data/fchk/h2o-restricted.fchk", molecule));

  GaussianSetTools tools(&molecule);

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);
  int homo = static_cast<int>(basis->electronCount(BasisSet::Paired)) / 2 - 1;

  // Create a small cube around the molecule
  Cube cube;
  cube.setLimits(molecule, 0.5f, 3.0f);

  // Fill the cube via the bulk method
  EXPECT_TRUE(tools.calculateMolecularOrbital(cube, homo));

  // Spot-check: compare cube values with per-point evaluation
  // Check corners and a few interior points
  unsigned int totalPoints = cube.data()->size();
  ASSERT_GT(totalPoints, 0u);

  // Test a selection of indices spread across the cube
  std::vector<unsigned int> testIndices = { 0, totalPoints / 4, totalPoints / 2,
                                            3 * totalPoints / 4,
                                            totalPoints - 1 };

  for (unsigned int idx : testIndices) {
    Vector3 pos = cube.position(idx);
    double expected = tools.calculateMolecularOrbital(pos, homo);
    float cubeVal = (*cube.data())[idx];
    EXPECT_NEAR(cubeVal, static_cast<float>(expected), 1e-5f)
      << "Mismatch at cube index " << idx << " position " << pos.transpose();
  }
}

// ---------------------------------------------------------------------------
// Water (UHF): alpha and beta orbitals
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, waterUnrestrictedAlphaBeta)
{
  Molecule molecule;
  ASSERT_TRUE(
    loadFchk(AVOGADRO_DATA "/data/fchk/h2o-unrestricted.fchk", molecule));

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);
  ASSERT_GT(basis->molecularOrbitalCount(BasisSet::Alpha), 0u);
  ASSERT_GT(basis->molecularOrbitalCount(BasisSet::Beta), 0u);

  // Alpha orbitals
  GaussianSetTools toolsAlpha(&molecule);
  toolsAlpha.setElectronType(BasisSet::Alpha);

  // Beta orbitals
  GaussianSetTools toolsBeta(&molecule);
  toolsBeta.setElectronType(BasisSet::Beta);

  Vector3 testPt = molecule.atomPosition3d(0); // oxygen

  double alphaVal = toolsAlpha.calculateMolecularOrbital(testPt, 0);
  double betaVal = toolsBeta.calculateMolecularOrbital(testPt, 0);

  // Both should be non-trivial
  EXPECT_GT(std::abs(alphaVal), 1e-3);
  EXPECT_GT(std::abs(betaVal), 1e-3);

  // No NaN/Inf
  EXPECT_FALSE(std::isnan(alphaVal));
  EXPECT_FALSE(std::isnan(betaVal));
}

TEST(GaussianSetToolsTest, waterUnrestrictedSpinDensity)
{
  Molecule molecule;
  ASSERT_TRUE(
    loadFchk(AVOGADRO_DATA "/data/fchk/h2o-unrestricted.fchk", molecule));

  GaussianSetTools tools(&molecule);
  auto points = generateTestPoints(molecule);

  // Spin density can be positive or negative, but should be finite
  for (const auto& pt : points) {
    double rho = tools.calculateSpinDensity(pt);
    EXPECT_FALSE(std::isnan(rho)) << "NaN at " << pt.transpose();
    EXPECT_FALSE(std::isinf(rho)) << "Inf at " << pt.transpose();
  }
}

// ---------------------------------------------------------------------------
// Benzene (RHF, 6-31G): S, SP shells, larger molecule
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, benzeneMolecularOrbital)
{
  Molecule molecule;
  ASSERT_TRUE(loadFchk(AVOGADRO_DATA "/data/fchk/benzene.fchk", molecule));

  GaussianSetTools tools(&molecule);

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);
  int homo = static_cast<int>(basis->electronCount(BasisSet::Paired)) / 2 - 1;
  ASSERT_GE(homo, 0);

  auto points = generateTestPoints(molecule);

  for (const auto& pt : points) {
    double val = tools.calculateMolecularOrbital(pt, homo);
    EXPECT_FALSE(std::isnan(val)) << "NaN at " << pt.transpose();
    EXPECT_FALSE(std::isinf(val)) << "Inf at " << pt.transpose();
  }

  // First MO (1s-like on carbon) should be large at atom center
  double mo0AtC =
    tools.calculateMolecularOrbital(molecule.atomPosition3d(0), 0);
  EXPECT_GT(std::abs(mo0AtC), 1e-2)
    << "First MO should be non-trivial at carbon center";
}

TEST(GaussianSetToolsTest, benzeneElectronDensity)
{
  Molecule molecule;
  ASSERT_TRUE(loadFchk(AVOGADRO_DATA "/data/fchk/benzene.fchk", molecule));

  GaussianSetTools tools(&molecule);
  auto points = generateTestPoints(molecule);

  for (const auto& pt : points) {
    double rho = tools.calculateElectronDensity(pt);
    EXPECT_GE(rho, -1e-10) << "Density should be non-negative at "
                           << pt.transpose();
    EXPECT_FALSE(std::isnan(rho));
  }
}

// ---------------------------------------------------------------------------
// NO2 (UHF): S, SP, D (cartesian) shells
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, no2CartesianD)
{
  Molecule molecule;
  ASSERT_TRUE(loadFchk(AVOGADRO_DATA "/data/fchk/no2.fchk", molecule));

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);

  // Verify D shells are present
  bool hasD = false;
  for (int sym : basis->symmetry()) {
    if (sym == GaussianSet::D) {
      hasD = true;
      break;
    }
  }
  EXPECT_TRUE(hasD) << "NO2 basis should contain cartesian D shells";

  GaussianSetTools toolsAlpha(&molecule);
  toolsAlpha.setElectronType(BasisSet::Alpha);

  auto points = generateTestPoints(molecule);

  for (const auto& pt : points) {
    double val = toolsAlpha.calculateMolecularOrbital(pt, 0);
    EXPECT_FALSE(std::isnan(val)) << "NaN at " << pt.transpose();
    EXPECT_FALSE(std::isinf(val)) << "Inf at " << pt.transpose();
  }

  // Electron density should be non-negative
  for (const auto& pt : points) {
    double rho = toolsAlpha.calculateElectronDensity(pt);
    EXPECT_GE(rho, -1e-10) << "Density should be non-negative at "
                           << pt.transpose();
  }
}

// ---------------------------------------------------------------------------
// d-only (RHF): pure D5 (spherical d) shells only
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, pureD5Shells)
{
  Molecule molecule;
  ASSERT_TRUE(loadFchk(AVOGADRO_DATA "/data/fchk/d-only.fchk", molecule));

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);

  // Verify D5 shells are present
  bool hasD5 = false;
  for (int sym : basis->symmetry()) {
    if (sym == GaussianSet::D5) {
      hasD5 = true;
      break;
    }
  }
  EXPECT_TRUE(hasD5) << "d-only basis should contain spherical D5 shells";

  GaussianSetTools tools(&molecule);
  auto points = generateTestPoints(molecule);

  for (const auto& pt : points) {
    double val = tools.calculateMolecularOrbital(pt, 0);
    EXPECT_FALSE(std::isnan(val)) << "NaN at " << pt.transpose();
    EXPECT_FALSE(std::isinf(val)) << "Inf at " << pt.transpose();
  }
}

// ---------------------------------------------------------------------------
// f-only (RHF): pure F7 (spherical f) shells only
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, pureF7Shells)
{
  Molecule molecule;
  ASSERT_TRUE(loadFchk(AVOGADRO_DATA "/data/fchk/f-only.fchk", molecule));

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);

  // Verify F7 shells are present
  bool hasF7 = false;
  for (int sym : basis->symmetry()) {
    if (sym == GaussianSet::F7) {
      hasF7 = true;
      break;
    }
  }
  EXPECT_TRUE(hasF7) << "f-only basis should contain spherical F7 shells";

  GaussianSetTools tools(&molecule);
  auto points = generateTestPoints(molecule);

  for (const auto& pt : points) {
    double val = tools.calculateMolecularOrbital(pt, 0);
    EXPECT_FALSE(std::isnan(val)) << "NaN at " << pt.transpose();
    EXPECT_FALSE(std::isinf(val)) << "Inf at " << pt.transpose();
  }
}

// ---------------------------------------------------------------------------
// CO cc-pV6Z (RHF): high angular momentum — S, P, D5, F7, G9, H11, I13
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, coHighAngularMomentumLoad)
{
  // CO cc-pV6Z has S, P, D5, F7, G9, H11, and I13 shells.
  // H11 and I13 are not yet implemented in GaussianSetTools (they contribute
  // zero), and the large basis can trigger out-of-bounds issues.
  // This test verifies the file loads correctly and has the expected shell
  // types.
  Molecule molecule;
  ASSERT_TRUE(loadFchk(AVOGADRO_DATA "/data/fchk/CO-cc-6Z.fchk", molecule));

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);

  // Check which shell types are present
  bool hasS = false, hasP = false, hasD5 = false, hasF7 = false, hasG9 = false;
  bool hasH = false, hasI = false;
  for (int sym : basis->symmetry()) {
    if (sym == GaussianSet::S)
      hasS = true;
    if (sym == GaussianSet::P)
      hasP = true;
    if (sym == GaussianSet::D5)
      hasD5 = true;
    if (sym == GaussianSet::F7)
      hasF7 = true;
    if (sym == GaussianSet::G9)
      hasG9 = true;
    if (sym == GaussianSet::H11)
      hasH = true;
    if (sym == GaussianSet::I13)
      hasI = true;
  }
  EXPECT_TRUE(hasS) << "CO cc-pV6Z should have S shells";
  EXPECT_TRUE(hasP) << "CO cc-pV6Z should have P shells";
  EXPECT_TRUE(hasD5) << "CO cc-pV6Z should have D5 shells";
  EXPECT_TRUE(hasF7) << "CO cc-pV6Z should have F7 shells";
  EXPECT_TRUE(hasG9) << "CO cc-pV6Z should have G9 shells";
  EXPECT_TRUE(hasH) << "CO cc-pV6Z should have H11 shells";
  EXPECT_TRUE(hasI) << "CO cc-pV6Z should have I13 shells";

  // TODO: Once H11 and I13 evaluation is implemented, add MO evaluation tests
  // here. Currently GaussianSetTools crashes on this basis due to the large
  // number of basis functions and unhandled shell types.
}

// ---------------------------------------------------------------------------
// MO orthonormality: numerical check on a small grid
//
// For an orthonormal set of MOs, integral(psi_i * psi_j dV) = delta_ij.
// We approximate this with a coarse grid sum as a sanity check.
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, waterMOOrthogonality)
{
  Molecule molecule;
  ASSERT_TRUE(
    loadFchk(AVOGADRO_DATA "/data/fchk/h2o-restricted.fchk", molecule));

  GaussianSetTools tools(&molecule);

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);
  unsigned int nMOs = basis->molecularOrbitalCount();
  ASSERT_GE(nMOs, 2u);

  // Create a cube for numerical integration
  // Use fine spacing (0.1 Ang) and generous padding for STO-3G
  Cube cube;
  cube.setLimits(molecule, 0.1f, 5.0f);

  int nx = cube.dimensions().x();
  int ny = cube.dimensions().y();
  int nz = cube.dimensions().z();
  // MO values are in Bohr^(-3/2), so integrate with dV in Bohr^3
  double a2b = Avogadro::ANGSTROM_TO_BOHR_D;
  double dV = cube.spacing().x() * cube.spacing().y() * cube.spacing().z() *
              a2b * a2b * a2b;

  // Evaluate MO 0 and MO 1 on the grid
  unsigned int totalPts = static_cast<unsigned int>(nx * ny * nz);
  std::vector<double> mo0(totalPts), mo1(totalPts);
  for (unsigned int i = 0; i < totalPts; ++i) {
    Vector3 pos = cube.position(i);
    mo0[i] = tools.calculateMolecularOrbital(pos, 0);
    mo1[i] = tools.calculateMolecularOrbital(pos, 1);
  }

  // Compute overlap integrals
  double overlap00 = 0.0, overlap11 = 0.0, overlap01 = 0.0;
  for (unsigned int i = 0; i < totalPts; ++i) {
    overlap00 += mo0[i] * mo0[i] * dV;
    overlap11 += mo1[i] * mo1[i] * dV;
    overlap01 += mo0[i] * mo1[i] * dV;
  }

  // Self-overlap should be close to 1 (normalization)
  EXPECT_NEAR(overlap00, 1.0, 0.15)
    << "MO 0 self-overlap should be ~1.0 (got " << overlap00 << ")";
  EXPECT_NEAR(overlap11, 1.0, 0.15)
    << "MO 1 self-overlap should be ~1.0 (got " << overlap11 << ")";

  // Cross-overlap should be close to 0 (orthogonality)
  EXPECT_NEAR(overlap01, 0.0, 0.1)
    << "MO 0-1 cross-overlap should be ~0.0 (got " << overlap01 << ")";
}

// ---------------------------------------------------------------------------
// Electron density integrates to ~N electrons (coarse numerical check)
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, waterDensityIntegration)
{
  Molecule molecule;
  ASSERT_TRUE(
    loadFchk(AVOGADRO_DATA "/data/fchk/h2o-restricted.fchk", molecule));

  GaussianSetTools tools(&molecule);

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);
  unsigned int nElectrons = basis->electronCount(BasisSet::Paired);
  ASSERT_GT(nElectrons, 0u);

  // Create a cube for numerical integration
  // Use fine spacing for accurate integration of compact STO-3G orbitals
  Cube cube;
  cube.setLimits(molecule, 0.1f, 5.0f);

  int nx = cube.dimensions().x();
  int ny = cube.dimensions().y();
  int nz = cube.dimensions().z();
  // Density is in Bohr^(-3), so integrate with dV in Bohr^3
  double a2b = Avogadro::ANGSTROM_TO_BOHR_D;
  double dV = cube.spacing().x() * cube.spacing().y() * cube.spacing().z() *
              a2b * a2b * a2b;
  unsigned int totalPts = static_cast<unsigned int>(nx * ny * nz);

  double integral = 0.0;
  for (unsigned int i = 0; i < totalPts; ++i) {
    Vector3 pos = cube.position(i);
    integral += tools.calculateElectronDensity(pos) * dV;
  }

  // Should integrate to approximately the number of electrons
  // Water has 10 electrons; fine grid should give ~5-10% error
  EXPECT_NEAR(integral, static_cast<double>(nElectrons), 2.0)
    << "Density integral should be ~" << nElectrons << " electrons (got "
    << integral << ")";
}

// ---------------------------------------------------------------------------
// Cube grid evaluation: compare bulk and per-point for electron density
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, waterDensityCubeConsistency)
{
  Molecule molecule;
  ASSERT_TRUE(
    loadFchk(AVOGADRO_DATA "/data/fchk/h2o-restricted.fchk", molecule));

  GaussianSetTools tools(&molecule);

  Cube cube;
  cube.setLimits(molecule, 0.5f, 3.0f);
  EXPECT_TRUE(tools.calculateElectronDensity(cube));

  unsigned int totalPoints = cube.data()->size();
  ASSERT_GT(totalPoints, 0u);

  // Spot-check several points
  std::vector<unsigned int> testIndices = { 0, totalPoints / 4, totalPoints / 2,
                                            3 * totalPoints / 4,
                                            totalPoints - 1 };

  for (unsigned int idx : testIndices) {
    Vector3 pos = cube.position(idx);
    double expected = tools.calculateElectronDensity(pos);
    float cubeVal = (*cube.data())[idx];
    EXPECT_NEAR(cubeVal, static_cast<float>(expected), 1e-5f)
      << "Density mismatch at cube index " << idx;
  }
}

// ---------------------------------------------------------------------------
// Multiple MOs: verify different MO indices give different results
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, differentMOsGiveDifferentValues)
{
  Molecule molecule;
  ASSERT_TRUE(loadFchk(AVOGADRO_DATA "/data/fchk/benzene.fchk", molecule));

  GaussianSetTools tools(&molecule);

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);
  unsigned int nMOs = basis->molecularOrbitalCount();
  ASSERT_GE(nMOs, 3u);

  // Pick a point slightly off-center from the first carbon
  Vector3 testPt = molecule.atomPosition3d(0) + Vector3(0.3, 0.2, 0.1);

  double mo0 = tools.calculateMolecularOrbital(testPt, 0);
  double mo1 = tools.calculateMolecularOrbital(testPt, 1);
  double mo2 = tools.calculateMolecularOrbital(testPt, 2);

  // At a generic point, different MOs should give different values
  bool allSame = (std::abs(mo0 - mo1) < 1e-10) && (std::abs(mo1 - mo2) < 1e-10);
  EXPECT_FALSE(allSame) << "Different MOs should produce different values "
                        << "at a generic point";
}

// ---------------------------------------------------------------------------
// C60 (large molecule): smoke test for performance and correctness
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, c60SmokeTest)
{
  Molecule molecule;
  ASSERT_TRUE(loadFchk(AVOGADRO_DATA "/data/fchk/c60.fchk", molecule));

  ASSERT_EQ(molecule.atomCount(), 60u);

  GaussianSetTools tools(&molecule);
  EXPECT_TRUE(tools.isValid());

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);

  int homo = static_cast<int>(basis->electronCount(BasisSet::Paired)) / 2 - 1;
  ASSERT_GE(homo, 0);

  // Evaluate at a few points — mainly checking no crash with many shells
  Vector3 center(0.0, 0.0, 0.0);
  double val = tools.calculateMolecularOrbital(center, homo);
  EXPECT_FALSE(std::isnan(val));
  EXPECT_FALSE(std::isinf(val));

  double rho = tools.calculateElectronDensity(center);
  EXPECT_GE(rho, 0.0);
  EXPECT_FALSE(std::isnan(rho));
}

// ---------------------------------------------------------------------------
// Methane (6-31G(d)): S, SP shells with d polarization
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, methanePolarization)
{
  Molecule molecule;
  ASSERT_TRUE(
    loadFchk(AVOGADRO_DATA "/data/fchk/methane-gaussian.fchk", molecule));

  ASSERT_EQ(molecule.atomCount(), 5u);

  GaussianSetTools tools(&molecule);

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);

  auto points = generateTestPoints(molecule);

  int homo = static_cast<int>(basis->electronCount(BasisSet::Paired)) / 2 - 1;
  ASSERT_GE(homo, 0);

  for (const auto& pt : points) {
    double val = tools.calculateMolecularOrbital(pt, homo);
    EXPECT_FALSE(std::isnan(val)) << "NaN at " << pt.transpose();
    EXPECT_FALSE(std::isinf(val)) << "Inf at " << pt.transpose();
  }

  // Density at carbon center should be significant
  double rhoC = tools.calculateElectronDensity(molecule.atomPosition3d(0));
  EXPECT_GT(rhoC, 1e-2);
}

// ---------------------------------------------------------------------------
// CO (6-31G): basic sanity for a diatomic
// ---------------------------------------------------------------------------

TEST(GaussianSetToolsTest, coDiatomic)
{
  Molecule molecule;
  ASSERT_TRUE(loadFchk(AVOGADRO_DATA "/data/fchk/co.fchk", molecule));

  ASSERT_EQ(molecule.atomCount(), 2u);

  GaussianSetTools tools(&molecule);
  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);

  int homo = static_cast<int>(basis->electronCount(BasisSet::Paired)) / 2 - 1;
  ASSERT_GE(homo, 0);

  // Bond midpoint
  Vector3 midpoint =
    0.5 * (molecule.atomPosition3d(0) + molecule.atomPosition3d(1));

  double moAtMid = tools.calculateMolecularOrbital(midpoint, homo);
  double rhoAtMid = tools.calculateElectronDensity(midpoint);

  EXPECT_FALSE(std::isnan(moAtMid));
  EXPECT_FALSE(std::isnan(rhoAtMid));
  EXPECT_GT(rhoAtMid, 1e-3) << "Density at bond midpoint should be significant";
}
