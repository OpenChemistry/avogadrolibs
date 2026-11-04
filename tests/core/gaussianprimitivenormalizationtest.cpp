/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/gaussianset.h>
#include <avogadro/core/gaussiansettools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <array>
#include <cmath>
#include <memory>
#include <string>
#include <vector>

using Avogadro::Vector3;
using Avogadro::Core::BasisSet;
using Avogadro::Core::GaussianSet;
using Avogadro::Core::GaussianSetTools;
using Avogadro::Core::Molecule;
using Normalization = Avogadro::Core::GaussianSet::PrimitiveNormalization;

namespace {

// GaussianSet::PrimitiveNormalization::AsIs uses each coefficient as the
// multiplier of the bare x^a y^b z^c exp(-alpha r^2), where Normalize first
// multiplies it by the primitive's normalization constant. The two modes
// therefore describe the same function when
//
//   AsIs coefficient * (MO coefficient of component k)
//     == raw coefficient * N(alpha, k) * (MO coefficient of component k).
//
// AsIs has a single coefficient per primitive but a Cartesian shell has
// components with different constants (xx and xy, say), so the AsIs basis
// gets c * N(alpha, component 0) and the remaining ratio N(k) / N(0), which
// does not depend on alpha, is moved into the MO matrix.
//
// Most tests take N from the Normalize basis itself (its gtoCN()), so they
// check the new mode against exactly what Normalize computes, to rounding
// error. closedFormMatchesNormalize() separately compares those constants
// with the closed formula
//
//   N(alpha; a, b, c) = (2 alpha / pi)^(3/4) (4 alpha)^(l/2)
//                       / sqrt((2a-1)!! (2b-1)!! (2c-1)!!)

using Powers = std::array<int, 3>;

struct CartesianCase
{
  GaussianSet::orbital type;
  std::string name;
  std::vector<Powers> components; // in the order the evaluator uses
  // Relative agreement of GaussianSet's constants with the closed formula.
  // The S, P and D constants in GaussianSet::initCalculation() are written
  // with only 9 or 10 significant digits, which leaves them off by (measured
  // against the formula) -5.0e-10 for S, +2.0e-10 for P and +2.1e-10 / -1.5e-10
  // for the two D constants. F and G are full precision. The tolerances are
  // those measured errors with about a factor of two to spare, so that a
  // wrong constant (errors of 1e-2 and up) cannot hide.
  double constantTolerance;
};

std::ostream& operator<<(std::ostream& out, const CartesianCase& shell)
{
  return out << shell.name;
}

double doubleFactorial(int odd)
{
  // (2n-1)!! with (-1)!! = 1
  double result = 1.0;
  for (int i = odd; i > 1; i -= 2)
    result *= i;
  return result;
}

double primitiveNormalization(double alpha, const Powers& p)
{
  const int l = p[0] + p[1] + p[2];
  return std::pow(2.0 * alpha / M_PI, 0.75) * std::pow(4.0 * alpha, 0.5 * l) /
         std::sqrt(doubleFactorial(2 * p[0] - 1) *
                   doubleFactorial(2 * p[1] - 1) *
                   doubleFactorial(2 * p[2] - 1));
}

struct Primitive
{
  double c;
  double a;
};

struct ShellSpec
{
  unsigned int atom;
  const CartesianCase* shell;
  std::vector<Primitive> primitives;
};

// Component orders follow the evaluator (GaussianSetTools::pointD, pointF,
// pointG, and the Gaussian/Molden ordering in initCalculation()).
const CartesianCase S_CASE{ GaussianSet::S, "S", { { 0, 0, 0 } }, 1e-9 };
const CartesianCase P_CASE{ GaussianSet::P,
                            "P",
                            { { 1, 0, 0 }, { 0, 1, 0 }, { 0, 0, 1 } },
                            5e-10 };
const CartesianCase D_CASE{ GaussianSet::D,
                            "D",
                            { { 2, 0, 0 },
                              { 0, 2, 0 },
                              { 0, 0, 2 },
                              { 1, 1, 0 },
                              { 1, 0, 1 },
                              { 0, 1, 1 } },
                            5e-10 };
const CartesianCase F_CASE{ GaussianSet::F,
                            "F",
                            { { 3, 0, 0 },
                              { 0, 3, 0 },
                              { 0, 0, 3 },
                              { 1, 2, 0 },
                              { 2, 1, 0 },
                              { 2, 0, 1 },
                              { 1, 0, 2 },
                              { 0, 1, 2 },
                              { 0, 2, 1 },
                              { 1, 1, 1 } },
                            1e-12 };
const CartesianCase G_CASE{ GaussianSet::G,
                            "G",
                            { { 4, 0, 0 },
                              { 0, 4, 0 },
                              { 0, 0, 4 },
                              { 3, 1, 0 },
                              { 3, 0, 1 },
                              { 1, 3, 0 },
                              { 0, 3, 1 },
                              { 1, 0, 3 },
                              { 0, 1, 3 },
                              { 2, 2, 0 },
                              { 2, 0, 2 },
                              { 0, 2, 2 },
                              { 2, 1, 1 },
                              { 1, 2, 1 },
                              { 1, 1, 2 } },
                            1e-12 };

// Two centres 0.9 Angstrom apart. The shell under test sits on both, with
// different contractions, between two s shells so that a wrong offset into
// the coefficient arrays shows up.
std::vector<ShellSpec> shellsFor(const CartesianCase& shell)
{
  return { { 0, &S_CASE, { { 0.4, 5.0 }, { 0.7, 1.2 } } },
           { 0, &shell, { { 0.6, 1.3 }, { 0.4, 0.35 } } },
           { 1, &shell, { { 1.0, 0.8 } } },
           { 1, &S_CASE, { { 0.5, 3.0 }, { 0.6, 0.5 } } } };
}

unsigned int functionCount(const std::vector<ShellSpec>& shells)
{
  unsigned int count = 0;
  for (const auto& spec : shells)
    count += static_cast<unsigned int>(spec.shell->components.size());
  return count;
}

// A deterministic, non-symmetric MO matrix (columns are MOs).
std::vector<double> moCoefficients(unsigned int nBasis)
{
  std::vector<double> mos(static_cast<size_t>(nBasis) * nBasis);
  for (size_t i = 0; i < mos.size(); ++i)
    mos[i] = std::sin(0.61 + 0.37 * static_cast<double>(i)) /
             (1.0 + 0.1 * static_cast<double>(i % nBasis));
  return mos;
}

// The reference description: raw coefficients, for Normalize.
GaussianSet* buildNormalized(Molecule& molecule,
                             const std::vector<ShellSpec>& shells)
{
  molecule.addAtom(8, Vector3(0.0, 0.0, 0.0));
  molecule.addAtom(1, Vector3(0.0, 0.0, 0.9));
  auto* basis = new GaussianSet;
  basis->setMolecule(&molecule);
  for (const auto& spec : shells) {
    unsigned int index = basis->addBasis(spec.atom, spec.shell->type);
    for (const auto& primitive : spec.primitives)
      basis->addGto(index, primitive.c, primitive.a);
  }
  basis->setMolecularOrbitals(moCoefficients(functionCount(shells)),
                              BasisSet::Paired);
  basis->setElectronCount(6);
  EXPECT_TRUE(basis->generateDensityMatrix());
  molecule.setBasisSet(basis);
  return basis;
}

// The same functions described for AsIs: coefficients pre-multiplied by the
// first component's constant, remaining ratios applied to the MO rows. The
// constants are read from the normalized basis (see the note at the top).
GaussianSet* buildPreMultiplied(Molecule& molecule,
                                const std::vector<ShellSpec>& shells,
                                GaussianSet& normalized)
{
  molecule.addAtom(8, Vector3(0.0, 0.0, 0.0));
  molecule.addAtom(1, Vector3(0.0, 0.0, 0.9));
  normalized.initCalculation();
  const std::vector<double> gtoCN = normalized.gtoCN();
  const std::vector<unsigned int> cIndices = normalized.cIndices();

  auto* basis = new GaussianSet;
  basis->setMolecule(&molecule);
  const unsigned int n = functionCount(shells);
  std::vector<double> mos = moCoefficients(n);
  unsigned int row = 0;
  for (size_t s = 0; s < shells.size(); ++s) {
    const ShellSpec& spec = shells[s];
    const size_t nComponents = spec.shell->components.size();
    unsigned int index = basis->addBasis(spec.atom, spec.shell->type);
    for (size_t j = 0; j < spec.primitives.size(); ++j)
      basis->addGto(index, gtoCN[cIndices[s] + j * nComponents],
                    spec.primitives[j].a);
    // The ratio is the same for every primitive; take the first.
    for (size_t k = 0; k < nComponents; ++k) {
      const double ratio = gtoCN[cIndices[s] + k] / gtoCN[cIndices[s]];
      for (unsigned int mo = 0; mo < n; ++mo)
        mos[row + static_cast<size_t>(mo) * n] *= ratio;
      ++row;
    }
  }
  basis->setMolecularOrbitals(mos, BasisSet::Paired);
  basis->setElectronCount(6);
  EXPECT_TRUE(basis->generateDensityMatrix());
  molecule.setBasisSet(basis);
  return basis;
}

const Vector3 POINTS[] = {
  Vector3(0.0, 0.0, 0.0),   Vector3(0.1, -0.2, 0.3), Vector3(0.0, 0.0, 0.9),
  Vector3(-0.4, 0.3, 0.5),  Vector3(0.5, 0.5, 1.2),  Vector3(-0.8, 0.1, -0.3),
  Vector3(0.3, -0.6, 0.45), Vector3(0.7, 0.2, 0.9),
};

// Relative agreement with a floor at the resolution of the summed terms
// (individual terms are O(1), so rounding leaves ~1e-16).
void expectClose(double actual, double expected, const std::string& what)
{
  EXPECT_NEAR(actual, expected, 1e-12 * std::abs(expected) + 1e-15) << what;
}

void expectSameValues(Molecule& actual, Molecule& expected,
                      const std::string& label)
{
  GaussianSetTools actualTools(&actual);
  GaussianSetTools expectedTools(&expected);
  const int nMOs =
    static_cast<int>(expected.basisSet()->molecularOrbitalCount());
  ASSERT_EQ(nMOs, static_cast<int>(actual.basisSet()->molecularOrbitalCount()));
  // Without a density matrix both densities are 0 and would compare equal.
  ASSERT_NE(expectedTools.calculateElectronDensity(POINTS[0]), 0.0) << label;
  ASSERT_NE(actualTools.calculateElectronDensity(POINTS[0]), 0.0) << label;
  int p = 0;
  for (const Vector3& point : POINTS) {
    expectClose(actualTools.calculateElectronDensity(point),
                expectedTools.calculateElectronDensity(point),
                label + " density at point " + std::to_string(p));
    for (int mo = 0; mo < nMOs; ++mo)
      expectClose(actualTools.calculateMolecularOrbital(point, mo),
                  expectedTools.calculateMolecularOrbital(point, mo),
                  label + " MO " + std::to_string(mo) + " at point " +
                    std::to_string(p));
    ++p;
  }
}

} // namespace

class GaussianPrimitiveNormalizationTest
  : public ::testing::TestWithParam<CartesianCase>
{};

TEST(GaussianPrimitiveNormalizationTest, defaultsToNormalize)
{
  GaussianSet basis;
  EXPECT_EQ(basis.primitiveNormalization(), Normalization::Normalize);
}

// The headline check: describing the same functions through AsIs gives the
// same orbitals and density as Normalize does.
TEST_P(GaussianPrimitiveNormalizationTest, asIsMatchesNormalize)
{
  const CartesianCase& shell = GetParam();
  const auto shells = shellsFor(shell);

  Molecule reference;
  GaussianSet* normalized = buildNormalized(reference, shells);

  Molecule molecule;
  GaussianSet* basis = buildPreMultiplied(molecule, shells, *normalized);
  ASSERT_TRUE(basis->setPrimitiveNormalization(Normalization::AsIs));
  EXPECT_EQ(basis->primitiveNormalization(), Normalization::AsIs);

  expectSameValues(molecule, reference, shell.name);
}

// Switching modes back and forth on one object must re-prepare the
// coefficients every time.
TEST_P(GaussianPrimitiveNormalizationTest, togglingReevaluatesCorrectly)
{
  const CartesianCase& shell = GetParam();
  const auto shells = shellsFor(shell);

  Molecule reference; // what AsIs of the pre-multiplied basis must give
  GaussianSet* normalized = buildNormalized(reference, shells);

  Molecule molecule;
  GaussianSet* basis = buildPreMultiplied(molecule, shells, *normalized);

  // The same pre-multiplied numbers, always normalized: what the object must
  // give while the flag is Normalize.
  Molecule normalizedPreMultiplied;
  buildPreMultiplied(normalizedPreMultiplied, shells, *normalized);

  expectSameValues(molecule, normalizedPreMultiplied,
                   shell.name + " (initial)");
  for (int pass = 0; pass < 2; ++pass) {
    ASSERT_TRUE(basis->setPrimitiveNormalization(Normalization::AsIs));
    expectSameValues(molecule, reference, shell.name + " (AsIs)");
    ASSERT_TRUE(basis->setPrimitiveNormalization(Normalization::Normalize));
    expectSameValues(molecule, normalizedPreMultiplied,
                     shell.name + " (Normalize)");
  }
}

// AsIs hands the raw coefficient to every Cartesian component of a primitive,
// in the layout GaussianSetTools indexes (primitive-major, component-minor).
TEST_P(GaussianPrimitiveNormalizationTest, asIsCoefficientsAreTheRawOnes)
{
  const CartesianCase& shell = GetParam();
  const auto shells = shellsFor(shell);

  Molecule reference;
  GaussianSet* normalized = buildNormalized(reference, shells);
  Molecule molecule;
  GaussianSet* basis = buildPreMultiplied(molecule, shells, *normalized);
  ASSERT_TRUE(basis->setPrimitiveNormalization(Normalization::AsIs));
  basis->initCalculation();

  const std::vector<double> gtoC = basis->gtoC();
  const std::vector<double> gtoCN = basis->gtoCN();
  const auto cIndices = basis->cIndices();
  const auto gtoIndices = basis->gtoIndices();
  ASSERT_EQ(cIndices.size(), shells.size());
  ASSERT_EQ(gtoIndices.size(), shells.size() + 1);

  size_t expectedSize = 0;
  for (size_t s = 0; s < shells.size(); ++s) {
    const size_t nComponents = shells[s].shell->components.size();
    EXPECT_EQ(cIndices[s], expectedSize);
    for (size_t j = 0; j < shells[s].primitives.size(); ++j)
      for (size_t k = 0; k < nComponents; ++k) {
        ASSERT_LT(expectedSize, gtoCN.size());
        EXPECT_EQ(gtoCN[expectedSize], gtoC[gtoIndices[s] + j])
          << "shell " << s << " primitive " << j << " component " << k;
        ++expectedSize;
      }
  }
  EXPECT_EQ(gtoCN.size(), expectedSize);
}

// The Normalize constants against the closed formula.
TEST_P(GaussianPrimitiveNormalizationTest, closedFormMatchesNormalize)
{
  const CartesianCase& shell = GetParam();
  const auto shells = shellsFor(shell);

  Molecule molecule;
  GaussianSet* basis = buildNormalized(molecule, shells);
  basis->initCalculation();
  const std::vector<double> gtoCN = basis->gtoCN();
  const auto cIndices = basis->cIndices();

  double worst = 0.0;
  for (size_t s = 0; s < shells.size(); ++s) {
    if (shells[s].shell != &shell)
      continue; // the s shells that frame it are covered by the S case
    const size_t nComponents = shells[s].shell->components.size();
    for (size_t j = 0; j < shells[s].primitives.size(); ++j)
      for (size_t k = 0; k < nComponents; ++k) {
        const Primitive& primitive = shells[s].primitives[j];
        const double expected =
          primitive.c *
          primitiveNormalization(primitive.a, shells[s].shell->components[k]);
        const double actual = gtoCN[cIndices[s] + j * nComponents + k];
        worst = std::max(worst, std::abs(actual / expected - 1.0));
      }
  }
  EXPECT_LT(worst, shell.constantTolerance) << shell.name;
}

INSTANTIATE_TEST_SUITE_P(
  CartesianShells, GaussianPrimitiveNormalizationTest,
  ::testing::Values(S_CASE, P_CASE, D_CASE, F_CASE, G_CASE),
  [](const ::testing::TestParamInfo<CartesianCase>& info) {
    return info.param.name;
  });

TEST(GaussianPrimitiveNormalizationTest, sphericalShellsRefuseAsIs)
{
  const GaussianSet::orbital spherical[] = { GaussianSet::D5, GaussianSet::F7,
                                             GaussianSet::G9, GaussianSet::H11,
                                             GaussianSet::I13 };
  for (GaussianSet::orbital type : spherical) {
    GaussianSet basis;
    basis.addBasis(0, GaussianSet::S);
    basis.addBasis(0, type);
    EXPECT_FALSE(basis.setPrimitiveNormalization(Normalization::AsIs))
      << "shell type " << type;
    EXPECT_EQ(basis.primitiveNormalization(), Normalization::Normalize);
    // Asking for the default is always fine.
    EXPECT_TRUE(basis.setPrimitiveNormalization(Normalization::Normalize));
  }
}

TEST(GaussianPrimitiveNormalizationTest, cartesianShellsAcceptAsIs)
{
  // Includes the Cartesian h and i types, which the evaluator does not
  // support but which are Cartesian all the same.
  GaussianSet basis;
  for (GaussianSet::orbital type :
       { GaussianSet::S, GaussianSet::P, GaussianSet::D, GaussianSet::F,
         GaussianSet::G, GaussianSet::H, GaussianSet::I })
    basis.addBasis(0, type);
  EXPECT_TRUE(basis.setPrimitiveNormalization(Normalization::AsIs));
  EXPECT_EQ(basis.primitiveNormalization(), Normalization::AsIs);
}

// A spherical shell added after the flag was set must not produce a basis
// in which only some shells are normalized: the whole basis is normalized
// and the flag goes back to Normalize.
TEST(GaussianPrimitiveNormalizationTest, laterSphericalShellForcesNormalize)
{
  Molecule molecule;
  molecule.addAtom(8, Vector3(0.0, 0.0, 0.0));
  auto* basis = new GaussianSet;
  basis->setMolecule(&molecule);
  molecule.setBasisSet(basis);

  unsigned int s = basis->addBasis(0, GaussianSet::S);
  basis->addGto(s, 0.7, 1.4);
  ASSERT_TRUE(basis->setPrimitiveNormalization(Normalization::AsIs));
  unsigned int d = basis->addBasis(0, GaussianSet::D5);
  basis->addGto(d, 0.9, 0.8);

  basis->initCalculation();
  EXPECT_EQ(basis->primitiveNormalization(), Normalization::Normalize);

  GaussianSet reference;
  unsigned int rs = reference.addBasis(0, GaussianSet::S);
  reference.addGto(rs, 0.7, 1.4);
  unsigned int rd = reference.addBasis(0, GaussianSet::D5);
  reference.addGto(rd, 0.9, 0.8);
  EXPECT_EQ(basis->gtoCN(), reference.gtoCN());
}

TEST(GaussianPrimitiveNormalizationTest, cloneKeepsTheFlag)
{
  GaussianSet basis;
  unsigned int s = basis.addBasis(0, GaussianSet::S);
  basis.addGto(s, 1.0, 1.0);
  ASSERT_TRUE(basis.setPrimitiveNormalization(Normalization::AsIs));

  std::unique_ptr<GaussianSet> cloned(basis.clone());
  EXPECT_EQ(cloned->primitiveNormalization(), Normalization::AsIs);
  cloned->initCalculation();
  EXPECT_EQ(cloned->gtoCN(), std::vector<double>{ 1.0 });
}

// Molecule shares its basis set between copies and clones it on first
// access (copy on write); the clone must carry the flag.
TEST(GaussianPrimitiveNormalizationTest, copiedMoleculeKeepsTheFlag)
{
  Molecule molecule;
  molecule.addAtom(8, Vector3(0.0, 0.0, 0.0));
  auto* basis = new GaussianSet;
  basis->setMolecule(&molecule);
  unsigned int s = basis->addBasis(0, GaussianSet::S);
  basis->addGto(s, 1.0, 1.0);
  ASSERT_TRUE(basis->setPrimitiveNormalization(Normalization::AsIs));
  molecule.setBasisSet(basis);

  Molecule copy(molecule);
  auto* copied = dynamic_cast<GaussianSet*>(copy.basisSet());
  ASSERT_NE(copied, nullptr);
  EXPECT_NE(copied, basis); // detached by the copy-on-write
  EXPECT_EQ(copied->primitiveNormalization(), Normalization::AsIs);
}
