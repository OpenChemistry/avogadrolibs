/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/gradients.h>
#include <avogadro/calc/uff.h>

#include <avogadro/core/angletools.h>
#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/io/xyzformat.h>

#include <cmath>
#include <vector>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;
using namespace Avogadro;

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Io::XyzFormat;

namespace {

constexpr Real kEpsilon = 1e-7;

void outOfPlaneNumerical(const Vector3& a, const Vector3& b, const Vector3& c,
                         const Vector3& d, Vector3& aGrad, Vector3& bGrad,
                         Vector3& cGrad, Vector3& dGrad)
{
  aGrad.setZero();
  bGrad.setZero();
  cGrad.setZero();
  dGrad.setZero();

  const Real angle0 = outOfPlaneAngle(a, b, c, d) * DEG_TO_RAD;

  for (int i = 0; i < 3; ++i) {
    Vector3 aPlus = a;
    aPlus[i] += kEpsilon;
    const Real anglePlus = outOfPlaneAngle(aPlus, b, c, d) * DEG_TO_RAD;
    aGrad[i] = (anglePlus - angle0) / kEpsilon;
  }

  for (int i = 0; i < 3; ++i) {
    Vector3 bPlus = b;
    bPlus[i] += kEpsilon;
    const Real anglePlus = outOfPlaneAngle(a, bPlus, c, d) * DEG_TO_RAD;
    bGrad[i] = (anglePlus - angle0) / kEpsilon;
  }

  for (int i = 0; i < 3; ++i) {
    Vector3 cPlus = c;
    cPlus[i] += kEpsilon;
    const Real anglePlus = outOfPlaneAngle(a, b, cPlus, d) * DEG_TO_RAD;
    cGrad[i] = (anglePlus - angle0) / kEpsilon;
  }

  for (int i = 0; i < 3; ++i) {
    Vector3 dPlus = d;
    dPlus[i] += kEpsilon;
    const Real anglePlus = outOfPlaneAngle(a, b, c, dPlus) * DEG_TO_RAD;
    dGrad[i] = (anglePlus - angle0) / kEpsilon;
  }
}

void expectCloseToNumeric(const Vector3& analytic, const Vector3& numeric)
{
  for (int i = 0; i < 3; ++i) {
    EXPECT_NEAR(analytic[i], numeric[i],
                std::max(1e-6, 0.1 * std::fabs(analytic[i])));
  }
}

} // namespace

// basic idea - go through a bunch of molecules
// calculate gradients and numeric gradients
// make sure the gradients are close for each atom

// Use a parameterized test fixture
class UffGradientTest : public ::testing::TestWithParam<const char*>
{};

// Parameterized test that works with any molecule file
TEST_P(UffGradientTest, GradientComparison)
{
  const char* filename = GetParam();

  XyzFormat xyz;
  Molecule molecule;

  std::string filepath = std::string(AVOGADRO_DATA) + "/data/xyz/" + filename;
  EXPECT_TRUE(xyz.readFile(filepath, molecule));
  ASSERT_EQ(xyz.error(), std::string());
  ASSERT_GT(molecule.atomCount(), 0);

  UFF uff;
  uff.setMolecule(&molecule);

  // get the positions
  unsigned int n = molecule.atomCount();
  Core::Array<Vector3> pos = molecule.atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> positions(p, 3 * n);

  Eigen::VectorXd analytical = Eigen::VectorXd::Zero(3 * n);
  Eigen::VectorXd numeric = Eigen::VectorXd::Zero(3 * n);
  uff.gradient(positions, analytical);
  uff.finiteGradient(positions, numeric);

  // assert that the components of each are finite
  ASSERT_TRUE(analytical.allFinite());
  ASSERT_TRUE(numeric.allFinite());

  // check numeric to analytic gradient for all atoms in a molecule
  for (int i = 0; i < 3 * n; i++) {
    // are these components within 10% of each other?
    EXPECT_NEAR(analytical[i], numeric[i],
                std::max(1e-6, 0.1 * std::fabs(analytical[i])));
  }
}

// Instantiate the test suite with different molecule files
INSTANTIATE_TEST_SUITE_P(
  UffTest, UffGradientTest,
  ::testing::Values("acetylene.xyz", "c2h2f2.xyz", "methane.xyz",
                    "formaldehyde.xyz", "H2O.xyz", "H2S.xyz", "H2Se.xyz",
                    "hooh.xyz", "PF5.xyz", "SF4.xyz", "SF6.xyz", "XeF4.xyz"
                    // Add more molecule files here as needed
                    ));

TEST(UffTest, OutOfPlaneGradientMatchesNumerical)
{
  const Vector3 a(0.0, 0.0, 0.0);
  const Vector3 b(1.0, 0.0, 0.0);
  const Vector3 c(0.0, 1.0, 0.0);
  const Vector3 d(0.2, 0.1, 1.0);

  Vector3 aGrad, bGrad, cGrad, dGrad;
  const Real angle = outOfPlaneGradient(a, b, c, d, aGrad, bGrad, cGrad, dGrad);
  (void)angle;

  Vector3 aNum, bNum, cNum, dNum;
  outOfPlaneNumerical(a, b, c, d, aNum, bNum, cNum, dNum);

  EXPECT_TRUE(aGrad.allFinite());
  EXPECT_TRUE(bGrad.allFinite());
  EXPECT_TRUE(cGrad.allFinite());
  EXPECT_TRUE(dGrad.allFinite());

  expectCloseToNumeric(aGrad, aNum);
  expectCloseToNumeric(bGrad, bNum);
  expectCloseToNumeric(cGrad, cNum);
  expectCloseToNumeric(dGrad, dNum);
}
