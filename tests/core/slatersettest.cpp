/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/slaterset.h>
#include <avogadro/core/slatersettools.h>
#include <avogadro/core/vector.h>

#include <Eigen/Dense>

#include <cmath>
#include <vector>

using Avogadro::ANGSTROM_TO_BOHR_D;
using Avogadro::Vector3;
using Avogadro::Core::Molecule;
using Avogadro::Core::SlaterSet;
using Avogadro::Core::SlaterSetTools;

namespace {

constexpr double kPi = 3.14159265358979323846;

// Build a molecule with one hydrogen atom at @a origin (angstrom) holding a
// single normalized STO. The overlap matrix and eigenvectors are the identity
// so molecular orbital 0 is exactly the basis function and the density is
// that function squared. Exponents are in inverse bohr, as MOPAC writes them.
// Returns the SlaterSet owned by the molecule.
SlaterSet* makeSingleSto(Molecule& mol, int type, int pqn, double zeta,
                         const Vector3& origin = Vector3::Zero())
{
  mol.addAtom(1).setPosition3d(origin);
  auto* basis = new SlaterSet;
  basis->addSlaterIndices({ 0 });
  basis->addSlaterTypes({ type });
  basis->addZetas({ zeta });
  basis->addPQNs({ pqn });
  Eigen::MatrixXd id = Eigen::MatrixXd::Identity(1, 1);
  basis->addOverlapMatrix(id);
  basis->addEigenVectors(id);
  basis->addDensityMatrix(id);
  mol.setBasisSet(basis);
  return basis;
}

// N r^(n-1) exp(-zeta r) radial normalization, everything in bohr:
// the integral of r^(2n) exp(-2 zeta r) dr = (2n)! / (2 zeta)^(2n+1).
double radialNorm(int n, double zeta)
{
  double fact = 1.0;
  for (int k = 2; k <= 2 * n; ++k)
    fact *= k;
  return std::pow(2.0 * zeta, n + 0.5) / std::sqrt(fact);
}

// Position given in bohr -> angstrom for the API.
Vector3 bohr(double x, double y, double z)
{
  return Vector3(x, y, z) / ANGSTROM_TO_BOHR_D;
}

const double points[][3] = { { 0.3, 0.0, 0.0 },
                             { 0.0, 1.1, 0.4 },
                             { 1.5, -0.7, 2.2 },
                             { -2.0, 1.0, -0.5 },
                             { 4.0, 3.0, -2.5 } };

} // namespace

TEST(SlaterSetTest, hydrogen1s)
{
  for (double zeta : { 1.0, 1.24 }) {
    Molecule mol;
    makeSingleSto(mol, SlaterSet::S, 1, zeta);
    SlaterSetTools tools(&mol);
    ASSERT_TRUE(tools.isValid());
    for (const auto& p : points) {
      double r = std::sqrt(p[0] * p[0] + p[1] * p[1] + p[2] * p[2]);
      double expected =
        std::sqrt(zeta * zeta * zeta / kPi) * std::exp(-zeta * r);
      EXPECT_NEAR(tools.calculateMolecularOrbital(bohr(p[0], p[1], p[2]), 0),
                  expected, 1e-9)
        << "zeta " << zeta << " r " << r;
      // Density matrix is the identity, so rho = psi^2.
      EXPECT_NEAR(tools.calculateElectronDensity(bohr(p[0], p[1], p[2])),
                  expected * expected, 1e-9);
    }
  }
}

TEST(SlaterSetTest, atomNotAtOrigin)
{
  Molecule mol;
  const Vector3 origin(1.0, -2.0, 0.5); // angstrom
  const double zeta = 1.0;
  makeSingleSto(mol, SlaterSet::S, 1, zeta, origin);
  SlaterSetTools tools(&mol);
  const Vector3 pos = origin + bohr(0.0, 1.5, 0.0);
  EXPECT_NEAR(tools.calculateMolecularOrbital(pos, 0),
              std::sqrt(1.0 / kPi) * std::exp(-1.5), 1e-9);
}

TEST(SlaterSetTest, hydrogen2s)
{
  const double zeta = 1.3;
  const int n = 2;
  Molecule mol;
  makeSingleSto(mol, SlaterSet::S, n, zeta);
  SlaterSetTools tools(&mol);
  for (const auto& p : points) {
    double r = std::sqrt(p[0] * p[0] + p[1] * p[1] + p[2] * p[2]);
    double expected = radialNorm(n, zeta) * r * std::exp(-zeta * r) *
                      std::sqrt(1.0 / (4.0 * kPi));
    EXPECT_NEAR(tools.calculateMolecularOrbital(bohr(p[0], p[1], p[2]), 0),
                expected, 1e-9)
      << "r " << r;
  }
}

TEST(SlaterSetTest, hydrogen2pz)
{
  const double zeta = 0.9;
  const int n = 2;
  Molecule mol;
  makeSingleSto(mol, SlaterSet::PZ, n, zeta);
  SlaterSetTools tools(&mol);
  for (const auto& p : points) {
    double r = std::sqrt(p[0] * p[0] + p[1] * p[1] + p[2] * p[2]);
    // N r^(n-1) exp(-zeta r) * sqrt(3/4pi) * z / r
    double expected = radialNorm(n, zeta) * std::pow(r, n - 1) *
                      std::exp(-zeta * r) * std::sqrt(3.0 / (4.0 * kPi)) *
                      p[2] / r;
    EXPECT_NEAR(tools.calculateMolecularOrbital(bohr(p[0], p[1], p[2]), 0),
                expected, 1e-9)
      << "r " << r;
  }
}

TEST(SlaterSetTest, higherPrincipalQuantumNumbers)
{
  // 3p_x and 3d_z2 check the r power for n > l + 1.
  const double zeta = 1.7;
  {
    Molecule mol;
    makeSingleSto(mol, SlaterSet::PX, 3, zeta);
    SlaterSetTools tools(&mol);
    for (const auto& p : points) {
      double r = std::sqrt(p[0] * p[0] + p[1] * p[1] + p[2] * p[2]);
      double expected = radialNorm(3, zeta) * r * r * std::exp(-zeta * r) *
                        std::sqrt(3.0 / (4.0 * kPi)) * p[0] / r;
      EXPECT_NEAR(tools.calculateMolecularOrbital(bohr(p[0], p[1], p[2]), 0),
                  expected, 1e-9);
    }
  }
  {
    Molecule mol;
    makeSingleSto(mol, SlaterSet::Z2, 3, zeta);
    SlaterSetTools tools(&mol);
    for (const auto& p : points) {
      double r2 = p[0] * p[0] + p[1] * p[1] + p[2] * p[2];
      double r = std::sqrt(r2);
      // Y20 = (1/4) sqrt(5/pi) (3 z^2 - r^2) / r^2
      double y20 = 0.25 * std::sqrt(5.0 / kPi) * (3.0 * p[2] * p[2] - r2) / r2;
      double expected = radialNorm(3, zeta) * r * r * std::exp(-zeta * r) * y20;
      EXPECT_NEAR(tools.calculateMolecularOrbital(bohr(p[0], p[1], p[2]), 0),
                  expected, 1e-9);
    }
  }
}

TEST(SlaterSetTest, reinitializationIsIdempotent)
{
  const double zeta = 1.1;
  Molecule mol;
  SlaterSet* basis = makeSingleSto(mol, SlaterSet::PZ, 2, zeta);
  SlaterSetTools tools(&mol);
  const Vector3 pos = bohr(0.4, -0.3, 1.2);
  const double first = tools.calculateMolecularOrbital(pos, 0);
  EXPECT_NE(first, 0.0);

  // Any setter that clears the initialized flag forces a second
  // initCalculation(); the exponents must not be converted twice.
  basis->addZetas({ zeta });
  EXPECT_NEAR(tools.calculateMolecularOrbital(pos, 0), first, 1e-12);
  basis->addPQNs({ 2 });
  basis->addSlaterTypes({ SlaterSet::PZ });
  EXPECT_NEAR(tools.calculateMolecularOrbital(pos, 0), first, 1e-12);
  EXPECT_NEAR(tools.calculateMolecularOrbital(pos, 0), first, 1e-12);
}

TEST(SlaterSetTest, normalization)
{
  // Integrate |psi|^2 on a midpoint grid, in bohr.
  const double zeta = 1.2;
  Molecule mol;
  makeSingleSto(mol, SlaterSet::PZ, 2, zeta);
  SlaterSetTools tools(&mol);
  const double h = 0.25;
  const int steps = 80; // box edge 20 bohr
  const double start = -0.5 * h * steps + 0.5 * h;
  double sum = 0.0;
  for (int i = 0; i < steps; ++i)
    for (int j = 0; j < steps; ++j)
      for (int k = 0; k < steps; ++k) {
        double v = tools.calculateMolecularOrbital(
          bohr(start + i * h, start + j * h, start + k * h), 0);
        sum += v * v;
      }
  EXPECT_NEAR(sum * h * h * h, 1.0, 5e-3);
}

TEST(SlaterSetTest, invalidInputs)
{
  // No molecule at all.
  SlaterSetTools none;
  EXPECT_FALSE(none.isValid());
  EXPECT_EQ(none.calculateMolecularOrbital(Vector3::Zero(), 0), 0.0);
  EXPECT_EQ(none.calculateElectronDensity(Vector3::Zero()), 0.0);

  // A molecule without a basis set.
  Molecule empty;
  SlaterSetTools nobasis(&empty);
  EXPECT_FALSE(nobasis.isValid());
  EXPECT_EQ(nobasis.calculateMolecularOrbital(Vector3::Zero(), 0), 0.0);

  // Orbital numbers count from zero: one past the end, and negatives, are
  // rejected rather than reading outside the matrix.
  Molecule mol;
  makeSingleSto(mol, SlaterSet::S, 1, 1.0);
  SlaterSetTools tools(&mol);
  EXPECT_NE(tools.calculateMolecularOrbital(bohr(0.5, 0, 0), 0), 0.0);
  EXPECT_EQ(tools.calculateMolecularOrbital(bohr(0.5, 0, 0), 1), 0.0);
  EXPECT_EQ(tools.calculateMolecularOrbital(bohr(0.5, 0, 0), -1), 0.0);
}

TEST(SlaterSetTest, badAtomIndexAndPqn)
{
  // The basis function points at an atom that does not exist.
  {
    Molecule mol;
    SlaterSet* basis = makeSingleSto(mol, SlaterSet::S, 1, 1.0);
    basis->addSlaterIndices({ 7 });
    SlaterSetTools tools(&mol);
    EXPECT_EQ(tools.calculateMolecularOrbital(bohr(0.5, 0, 0), 0), 0.0);
    basis->addSlaterIndices({ -1 });
    EXPECT_EQ(tools.calculateMolecularOrbital(bohr(0.5, 0, 0), 0), 0.0);
  }
  // A negative principal quantum number must not recurse or overflow.
  {
    Molecule mol;
    makeSingleSto(mol, SlaterSet::S, -3, 1.0);
    SlaterSetTools tools(&mol);
    EXPECT_EQ(tools.calculateMolecularOrbital(bohr(0.5, 0, 0), 0), 0.0);
  }
  // Large principal quantum numbers: (2n)! overflows 32-bit integers.
  {
    Molecule mol;
    makeSingleSto(mol, SlaterSet::S, 7, 2.0);
    SlaterSetTools tools(&mol);
    const double r = 3.0;
    double expected = radialNorm(7, 2.0) * std::pow(r, 6) * std::exp(-2.0 * r) *
                      std::sqrt(1.0 / (4.0 * kPi));
    EXPECT_NEAR(tools.calculateMolecularOrbital(bohr(r, 0, 0), 0), expected,
                1e-9 * std::abs(expected) + 1e-15);
  }
}
