/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/gaussiansettools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <cmath>
#include <string>
#include <vector>

using Avogadro::Vector3;
using Avogadro::Core::BasisSet;
using Avogadro::Core::Cube;
using Avogadro::Core::GaussianSet;
using Avogadro::Core::GaussianSetTools;
using Avogadro::Core::Molecule;

namespace {

// Every basis function this code builds must be normalized: the overlap of
// a primitive Gaussian shell component with itself is 1 by construction of
// the normalization constants in GaussianSet::initCalculation. Spherical
// (pure-l) shells must additionally be orthogonal to each other and to
// every lower-l shell on the same centre, because real solid harmonics of
// different (l, m) are orthogonal over the sphere.
//
// Cartesian shells are deliberately *not* subject to the orthogonality
// checks: x^2 exp(-a r^2) genuinely contains an s component (x^2 = r^2/3 +
// pure-l=2 part), so a non-zero overlap with an s function is correct
// behaviour there, not a bug.
//
// These invariants are checked by numerical integration of the real
// evaluator, GaussianSetTools::calculateMolecularOrbital(). With the MO
// coefficient matrix set to the identity, MO j is exactly AO j, so this
// exercises the same pointS/pointP/pointD/... code path that renders
// orbitals rather than a reimplementation of it.

// Exponent shared by every shell in the test basis. Using one exponent
// everywhere means all pairwise products are exp(-2 * ALPHA * r^2), which
// the Gauss-Hermite rule below integrates exactly.
const double ALPHA = 1.0;

// 6-point Gauss-Hermite nodes and weights for the weight function
// exp(-u^2). The integrands here are (polynomial of per-axis degree <= 8)
// times exp(-2 * ALPHA * r^2); a 6-point rule is exact through degree
// 2*6 - 1 = 11, so these overlaps are exact to machine precision rather
// than merely convergent.
//
// 6 points is also deliberately not more: GaussianSetTools applies a
// per-shell distance cutoff (calculateShellCutoff), and a higher-order rule
// would place its outermost nodes beyond that cutoff, where the evaluator
// legitimately returns zero and the quadrature would lose its exactness.
// The smallest cutoff in this basis (the s shell) is about 3.25 bohr; the
// furthest node used here is at radius 2.35 * sqrt(3) / sqrt(2) ~ 2.88.
struct QuadPoint
{
  double node;
  double weight;
};

const QuadPoint HERMITE[] = {
  { -2.3506049736744923, 0.0045300099055088352 },
  { -1.3358490740136970, 0.15706732032285647 },
  { -0.4360774119276165, 0.72462959522439241 },
  { +0.4360774119276165, 0.72462959522439241 },
  { +1.3358490740136970, 0.15706732032285647 },
  { +2.3506049736744923, 0.0045300099055088352 },
};
const int HERMITE_COUNT = 6;

// Positions are handed to calculateMolecularOrbital() in Angstrom and
// converted to Bohr internally, so the quadrature nodes (which live in
// Bohr, where the Gaussians are defined) have to be converted on the way
// in.
const double BOHR_TO_ANGSTROM = 0.52917721092;

// The probe shells prepended to every test basis, so that a spherical test
// shell can be checked for contamination by a lower angular momentum. Only
// same-parity shells can contaminate (an even-l function is orthogonal to
// every odd-l function by parity alone), but including all four costs
// nothing and keeps the bookkeeping simple.
struct ProbeShell
{
  GaussianSet::orbital type;
  int components;
  int l;
};

const ProbeShell PROBES[] = {
  { GaussianSet::S, 1, 0 },
  { GaussianSet::P, 3, 1 },
  { GaussianSet::D5, 5, 2 },
  { GaussianSet::F7, 7, 3 },
};
const int PROBE_COUNT = 4;
const int PROBE_AO_COUNT = 1 + 3 + 5 + 7;

struct ShellCase
{
  GaussianSet::orbital type;
  std::string name;
  int components;
  int l;
  bool pure; // true for a pure-l (spherical) shell; see note above
};

// Printed by gtest in the test name, so a failure says which shell broke.
std::ostream& operator<<(std::ostream& out, const ShellCase& shell)
{
  return out << shell.name;
}

} // namespace

class GaussianShellNormalizationTest
  : public ::testing::TestWithParam<ShellCase>
{
protected:
  // Builds a single-atom molecule whose basis is the four probe shells
  // followed by the shell under test, every shell a single primitive with
  // exponent ALPHA and contraction coefficient 1. The MO matrix is the
  // identity, so MO j evaluates AO j.
  void SetUp() override
  {
    const ShellCase& shell = GetParam();

    m_molecule.addAtom(6, Vector3(0.0, 0.0, 0.0));

    auto* basis = new GaussianSet;
    basis->setMolecule(&m_molecule);
    for (int i = 0; i < PROBE_COUNT; ++i) {
      unsigned int s = basis->addBasis(0, PROBES[i].type);
      basis->addGto(s, 1.0, ALPHA);
    }
    unsigned int s = basis->addBasis(0, shell.type);
    basis->addGto(s, 1.0, ALPHA);

    m_aoCount = PROBE_AO_COUNT + shell.components;

    std::vector<double> identity(
      static_cast<size_t>(m_aoCount) * static_cast<size_t>(m_aoCount), 0.0);
    for (int i = 0; i < m_aoCount; ++i)
      identity[static_cast<size_t>(i) * m_aoCount + i] = 1.0;
    basis->setMolecularOrbitals(identity, BasisSet::Paired);

    // The molecule takes ownership of the basis set.
    m_molecule.setBasisSet(basis);
    m_tools = new GaussianSetTools(&m_molecule);
  }

  void TearDown() override { delete m_tools; }

  // <phi_i | phi_j> by Gauss-Hermite quadrature. The evaluator returns
  // phi = P(r) exp(-ALPHA r^2), so the product carries exp(-2 ALPHA r^2);
  // multiplying it back out leaves the bare polynomial for the rule to
  // integrate against its own exp(-u^2) weight.
  double overlap(int i, int j) const
  {
    const double scale = std::sqrt(2.0 * ALPHA);
    double sum = 0.0;
    for (int a = 0; a < HERMITE_COUNT; ++a) {
      const double x = HERMITE[a].node / scale;
      for (int b = 0; b < HERMITE_COUNT; ++b) {
        const double y = HERMITE[b].node / scale;
        for (int c = 0; c < HERMITE_COUNT; ++c) {
          const double z = HERMITE[c].node / scale;
          const Vector3 position(x * BOHR_TO_ANGSTROM, y * BOHR_TO_ANGSTROM,
                                 z * BOHR_TO_ANGSTROM);
          const double r2 = x * x + y * y + z * z;
          const double vi = m_tools->calculateMolecularOrbital(position, i);
          const double vj = m_tools->calculateMolecularOrbital(position, j);
          sum += HERMITE[a].weight * HERMITE[b].weight * HERMITE[c].weight *
                 vi * vj * std::exp(2.0 * ALPHA * r2);
        }
      }
    }
    return sum / std::pow(2.0 * ALPHA, 1.5);
  }

  Molecule m_molecule;
  GaussianSetTools* m_tools = nullptr;
  int m_aoCount = 0;
};

// Guards the quadrature itself. If the shell cutoff ever tightens enough to
// clip a node, or the node table is mistranscribed, this fails first and
// every other failure in this file should be read in that light.
TEST_P(GaussianShellNormalizationTest, quadratureIntegratesTheSShellExactly)
{
  EXPECT_NEAR(overlap(0, 0), 1.0, 1e-6);
}

// The diagonal check. This is what catches a wrong normalization constant:
// the spherical g shell used one m-independent constant where three are
// needed (norms of 105, 105/8 and 21/2 instead of 1), the Cartesian g shell
// used the wrong double-factorial divisors, and d0 came out at 8/3.
TEST_P(GaussianShellNormalizationTest, shellsAreNormalized)
{
  const ShellCase& shell = GetParam();
  for (int c = 0; c < shell.components; ++c) {
    const int ao = PROBE_AO_COUNT + c;
    EXPECT_NEAR(overlap(ao, ao), 1.0, 1e-6)
      << shell.name << " component " << c << " is not normalized";
  }
}

// The off-diagonal check, within one shell. Note that this does NOT catch
// the historical d0 bug: -(xx + yy) is orthogonal to xz, yz, xy by parity
// and to (xx - yy) by x<->y antisymmetry, so the whole off-diagonal block
// was clean while d0 was not a d function at all. It is still worth
// asserting -- it pins the relative phases and shapes of the components.
TEST_P(GaussianShellNormalizationTest, sphericalShellComponentsAreOrthogonal)
{
  const ShellCase& shell = GetParam();
  if (!shell.pure)
    GTEST_SKIP() << "Cartesian components are not mutually orthogonal";

  for (int a = 0; a < shell.components; ++a) {
    for (int b = a + 1; b < shell.components; ++b) {
      EXPECT_NEAR(overlap(PROBE_AO_COUNT + a, PROBE_AO_COUNT + b), 0.0, 1e-6)
        << shell.name << " components " << a << " and " << b
        << " are not orthogonal";
    }
  }
}

// The check that actually pins down "is this really an l-shell": a pure-l
// function must be orthogonal to every function of lower l on the same
// centre. This is what the d0 bug violated (<d0|s> was -1.1547), and it is
// the only one of these three tests that would reject the tempting wrong
// fix of simply rescaling the broken d0 to unit norm -- that variant has
// norm 1 and a clean off-diagonal block, but is still 70% s.
TEST_P(GaussianShellNormalizationTest,
       pureShellsAreOrthogonalToLowerAngularMomenta)
{
  const ShellCase& shell = GetParam();
  if (!shell.pure)
    GTEST_SKIP() << "Cartesian shells legitimately contain lower-l parts";

  int probeAo = 0;
  for (int p = 0; p < PROBE_COUNT; ++p) {
    if (PROBES[p].l >= shell.l) {
      probeAo += PROBES[p].components;
      continue;
    }
    for (int pc = 0; pc < PROBES[p].components; ++pc) {
      for (int c = 0; c < shell.components; ++c) {
        EXPECT_NEAR(overlap(probeAo + pc, PROBE_AO_COUNT + c), 0.0, 1e-6)
          << shell.name << " component " << c
          << " has a non-zero overlap with an l=" << PROBES[p].l
          << " function: it is not a pure l=" << shell.l << " function";
      }
    }
    probeAo += PROBES[p].components;
  }
}

// GaussianSetTools keeps two independent implementations of every shell:
// the point* methods exercised above, and the grid* free functions used to
// fill a Cube, which is the path that actually renders isosurfaces. They
// duplicate the angular polynomials, so a fix applied to only one of them
// leaves the two silently disagreeing -- exactly the failure mode that
// hid the d0 bug in gridD5. Evaluate both on the same coordinates and
// require them to agree.
TEST_P(GaussianShellNormalizationTest, gridAndPointPathsAgree)
{
  const ShellCase& shell = GetParam();

  // Cube limits are in Angstrom. A coarse grid is plenty: we are comparing
  // two evaluators against each other, not integrating anything.
  Cube cube;
  const double extent = 2.0;
  ASSERT_TRUE(cube.setLimits(Vector3(-extent, -extent, -extent),
                             Vector3(extent, extent, extent), 0.5f));

  for (int c = 0; c < shell.components; ++c) {
    const int mo = PROBE_AO_COUNT + c;
    ASSERT_TRUE(m_tools->calculateMolecularOrbital(cube, mo));

    const Avogadro::Vector3i dim = cube.dimensions();
    double worst = 0.0;
    for (int i = 0; i < dim.x(); ++i) {
      for (int j = 0; j < dim.y(); ++j) {
        for (int k = 0; k < dim.z(); ++k) {
          const unsigned int index =
            static_cast<unsigned int>((i * dim.y() + j) * dim.z() + k);
          const double fromGrid = cube.value(i, j, k);
          const double fromPoint =
            m_tools->calculateMolecularOrbital(cube.position(index), mo);
          worst = std::max(worst, std::abs(fromGrid - fromPoint));
        }
      }
    }
    // Cube stores floats, so the tolerance is set by float precision on
    // values of order 1, not by the evaluators.
    EXPECT_LT(worst, 1e-5) << shell.name << " component " << c
                           << ": grid and point evaluators disagree";
  }
}

INSTANTIATE_TEST_SUITE_P(
  Shells, GaussianShellNormalizationTest,
  ::testing::Values(ShellCase{ GaussianSet::S, "S", 1, 0, true },
                    ShellCase{ GaussianSet::P, "P", 3, 1, true },
                    ShellCase{ GaussianSet::D, "D_cartesian", 6, 2, false },
                    ShellCase{ GaussianSet::D5, "D5_spherical", 5, 2, true },
                    ShellCase{ GaussianSet::F, "F_cartesian", 10, 3, false },
                    ShellCase{ GaussianSet::F7, "F7_spherical", 7, 3, true },
                    ShellCase{ GaussianSet::G, "G_cartesian", 15, 4, false },
                    ShellCase{ GaussianSet::G9, "G9_spherical", 9, 4, true }),
  [](const ::testing::TestParamInfo<ShellCase>& info) {
    return info.param.name;
  });
