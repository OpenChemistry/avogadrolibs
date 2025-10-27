/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/gradients.h>
#include <avogadro/core/angletools.h>
#include <avogadro/core/vector.h>

#include <cmath>
#include <vector>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;
using namespace Avogadro;

using Avogadro::Vector3;

// Numerical gradient calculation helper
class NumericalGradient
{
public:
  static constexpr Real epsilon = 1e-7;

  // Calculate numerical gradient for angle
  static void angleNumerical(const Vector3& a, const Vector3& b,
                             const Vector3& c, Vector3& aGrad, Vector3& bGrad,
                             Vector3& cGrad)
  {
    aGrad.setZero();
    bGrad.setZero();
    cGrad.setZero();

    // Get the baseline angle
    Real angle0 = calculateAngle(a, b, c) * DEG_TO_RAD;

    // Numerical gradient for point a
    for (int i = 0; i < 3; ++i) {
      Vector3 aPlus = a;
      aPlus[i] += epsilon;
      Real anglePlus = calculateAngle(aPlus, b, c) * DEG_TO_RAD;
      aGrad[i] = (anglePlus - angle0) / epsilon;
    }

    // Numerical gradient for point b
    for (int i = 0; i < 3; ++i) {
      Vector3 bPlus = b;
      bPlus[i] += epsilon;
      Real anglePlus = calculateAngle(a, bPlus, c) * DEG_TO_RAD;
      bGrad[i] = (anglePlus - angle0) / epsilon;
    }

    // Numerical gradient for point c
    for (int i = 0; i < 3; ++i) {
      Vector3 cPlus = c;
      cPlus[i] += epsilon;
      Real anglePlus = calculateAngle(a, b, cPlus) * DEG_TO_RAD;
      cGrad[i] = (anglePlus - angle0) / epsilon;
    }
  }

  // Calculate numerical gradient for dihedral
  static void dihedralNumerical(const Vector3& i, const Vector3& j,
                                const Vector3& k, const Vector3& l,
                                Vector3& iGrad, Vector3& jGrad, Vector3& kGrad,
                                Vector3& lGrad)
  {
    iGrad.setZero();
    jGrad.setZero();
    kGrad.setZero();
    lGrad.setZero();

    Real phi0 = calculateDihedral(i, j, k, l) * DEG_TO_RAD;

    // Numerical gradient for point i
    for (int idx = 0; idx < 3; ++idx) {
      Vector3 iPlus = i;
      iPlus[idx] += epsilon;
      Real phiPlus = calculateDihedral(iPlus, j, k, l) * DEG_TO_RAD;
      Real diff = phiPlus - phi0;
      // Handle wrapping around -pi/pi
      if (diff > M_PI)
        diff -= 2 * M_PI;
      if (diff < -M_PI)
        diff += 2 * M_PI;
      iGrad[idx] = diff / epsilon;
    }

    // Numerical gradient for point j
    for (int idx = 0; idx < 3; ++idx) {
      Vector3 jPlus = j;
      jPlus[idx] += epsilon;
      Real phiPlus = calculateDihedral(i, jPlus, k, l) * DEG_TO_RAD;
      Real diff = phiPlus - phi0;
      if (diff > M_PI)
        diff -= 2 * M_PI;
      if (diff < -M_PI)
        diff += 2 * M_PI;
      jGrad[idx] = diff / epsilon;
    }

    // Numerical gradient for point k
    for (int idx = 0; idx < 3; ++idx) {
      Vector3 kPlus = k;
      kPlus[idx] += epsilon;
      Real phiPlus = calculateDihedral(i, j, kPlus, l) * DEG_TO_RAD;
      Real diff = phiPlus - phi0;
      if (diff > M_PI)
        diff -= 2 * M_PI;
      if (diff < -M_PI)
        diff += 2 * M_PI;
      kGrad[idx] = diff / epsilon;
    }

    // Numerical gradient for point l
    for (int idx = 0; idx < 3; ++idx) {
      Vector3 lPlus = l;
      lPlus[idx] += epsilon;
      Real phiPlus = calculateDihedral(i, j, k, lPlus) * DEG_TO_RAD;
      Real diff = phiPlus - phi0;
      if (diff > M_PI)
        diff -= 2 * M_PI;
      if (diff < -M_PI)
        diff += 2 * M_PI;
      lGrad[idx] = diff / epsilon;
    }
  }
};

// Helper function to check if a vector contains NaN or Inf
bool hasNaNOrInf(const Vector3& v)
{
  return std::isnan(v[0]) || std::isnan(v[1]) || std::isnan(v[2]) ||
         std::isinf(v[0]) || std::isinf(v[1]) || std::isinf(v[2]);
}

// Test fixture for angle gradients
class AngleGradientTest : public ::testing::Test
{
protected:
  void checkGradientsValid(const Vector3& aGrad, const Vector3& bGrad,
                           const Vector3& cGrad)
  {
    EXPECT_FALSE(hasNaNOrInf(aGrad)) << "aGrad has NaN or Inf";
    EXPECT_FALSE(hasNaNOrInf(bGrad)) << "bGrad has NaN or Inf";
    EXPECT_FALSE(hasNaNOrInf(cGrad)) << "cGrad has NaN or Inf";
  }

  void compareWithNumerical(const Vector3& a, const Vector3& b,
                            const Vector3& c, Real tolerance = 1e-4)
  {
    Vector3 aGrad, bGrad, cGrad;
    Vector3 aGradNum, bGradNum, cGradNum;

    angleGradient(a, b, c, aGrad, bGrad, cGrad);
    NumericalGradient::angleNumerical(a, b, c, aGradNum, bGradNum, cGradNum);

    EXPECT_NEAR((aGrad - aGradNum).norm(), 0.0, tolerance) << "aGrad mismatch";
    EXPECT_NEAR((bGrad - bGradNum).norm(), 0.0, tolerance) << "bGrad mismatch";
    EXPECT_NEAR((cGrad - cGradNum).norm(), 0.0, tolerance) << "cGrad mismatch";
  }
};

// Test fixture for dihedral gradients
class DihedralGradientTest : public ::testing::Test
{
protected:
  void checkGradientsValid(const Vector3& iGrad, const Vector3& jGrad,
                           const Vector3& kGrad, const Vector3& lGrad)
  {
    EXPECT_FALSE(hasNaNOrInf(iGrad)) << "iGrad has NaN or Inf";
    EXPECT_FALSE(hasNaNOrInf(jGrad)) << "jGrad has NaN or Inf";
    EXPECT_FALSE(hasNaNOrInf(kGrad)) << "kGrad has NaN or Inf";
    EXPECT_FALSE(hasNaNOrInf(lGrad)) << "lGrad has NaN or Inf";
  }

  void compareWithNumerical(const Vector3& i, const Vector3& j,
                            const Vector3& k, const Vector3& l,
                            Real tolerance = 1e-4)
  {
    Vector3 iGrad, jGrad, kGrad, lGrad;
    Vector3 iGradNum, jGradNum, kGradNum, lGradNum;

    dihedralGradient(i, j, k, l, iGrad, jGrad, kGrad, lGrad);
    NumericalGradient::dihedralNumerical(i, j, k, l, iGradNum, jGradNum,
                                         kGradNum, lGradNum);

    EXPECT_NEAR((iGrad - iGradNum).norm(), 0.0, tolerance) << "iGrad mismatch";
    EXPECT_NEAR((jGrad - jGradNum).norm(), 0.0, tolerance) << "jGrad mismatch";
    EXPECT_NEAR((kGrad - kGradNum).norm(), 0.0, tolerance) << "kGrad mismatch";
    EXPECT_NEAR((lGrad - lGradNum).norm(), 0.0, tolerance) << "lGrad mismatch";
  }
};

// Angle Gradient Tests

TEST_F(AngleGradientTest, StandardAngle90Degrees)
{
  Vector3 a(1.0, 0.0, 0.0);
  Vector3 b(0.0, 0.0, 0.0);
  Vector3 c(0.0, 1.0, 0.0);

  Vector3 aGrad, bGrad, cGrad;
  Real angle = angleGradient(a, b, c, aGrad, bGrad, cGrad);

  EXPECT_NEAR(angle, M_PI / 2, 1e-6);
  checkGradientsValid(aGrad, bGrad, cGrad);
  compareWithNumerical(a, b, c);
}

TEST_F(AngleGradientTest, StandardAngle120Degrees)
{
  Vector3 a(1.0, 0.0, 0.0);
  Vector3 b(0.0, 0.0, 0.0);
  Vector3 c(-0.5, sqrt(3.0) / 2.0, 0.0);

  Vector3 aGrad, bGrad, cGrad;
  Real angle = angleGradient(a, b, c, aGrad, bGrad, cGrad);

  EXPECT_NEAR(angle, 2 * M_PI / 3, 1e-6);
  checkGradientsValid(aGrad, bGrad, cGrad);
  compareWithNumerical(a, b, c);
}

TEST_F(AngleGradientTest, StandardAngle60Degrees)
{
  Vector3 a(1.0, 0.0, 0.0);
  Vector3 b(0.0, 0.0, 0.0);
  Vector3 c(0.5, sqrt(3.0) / 2.0, 0.0);

  Vector3 aGrad, bGrad, cGrad;
  Real angle = angleGradient(a, b, c, aGrad, bGrad, cGrad);

  EXPECT_NEAR(angle, M_PI / 3, 1e-6);
  checkGradientsValid(aGrad, bGrad, cGrad);
  compareWithNumerical(a, b, c);
}

TEST_F(AngleGradientTest, NearLinear180Degrees)
{
  Vector3 a(1.0, 0.0, 0.0);
  Vector3 b(0.0, 0.0, 0.0);
  Vector3 c(-1.0, 0.0, 0.0);

  Vector3 aGrad, bGrad, cGrad;
  Real angle = angleGradient(a, b, c, aGrad, bGrad, cGrad);

  EXPECT_NEAR(angle, M_PI, 1e-6);
  checkGradientsValid(aGrad, bGrad, cGrad);
}

TEST_F(AngleGradientTest, NearLinear179Degrees)
{
  Vector3 a(1.0, 0.0, 0.0);
  Vector3 b(0.0, 0.0, 0.0);
  Vector3 c(-1.0, 0.01, 0.0);

  Vector3 aGrad, bGrad, cGrad;
  Real angle = angleGradient(a, b, c, aGrad, bGrad, cGrad);

  checkGradientsValid(aGrad, bGrad, cGrad);
  compareWithNumerical(a, b, c);
}

TEST_F(AngleGradientTest, NearZero1Degree)
{
  Vector3 a(1.0, 0.0, 0.0);
  Vector3 b(0.0, 0.0, 0.0);
  Vector3 c(1.0, 0.01, 0.0);

  Vector3 aGrad, bGrad, cGrad;
  Real angle = angleGradient(a, b, c, aGrad, bGrad, cGrad);

  checkGradientsValid(aGrad, bGrad, cGrad);
}

TEST_F(AngleGradientTest, VaryingBondLengths)
{
  std::vector<Real> bondLengths = { 0.5, 1.0, 1.5, 2.0, 3.0, 5.0 };

  for (Real r1 : bondLengths) {
    for (Real r2 : bondLengths) {
      Vector3 a(r1, 0.0, 0.0);
      Vector3 b(0.0, 0.0, 0.0);
      Vector3 c(0.0, r2, 0.0);

      Vector3 aGrad, bGrad, cGrad;
      angleGradient(a, b, c, aGrad, bGrad, cGrad);

      checkGradientsValid(aGrad, bGrad, cGrad);
      compareWithNumerical(a, b, c);
    }
  }
}

TEST_F(AngleGradientTest, RangeOfAngles)
{
  // Test angles from 10 to 170 degrees in 10 degree increments
  for (int angleDeg = 10; angleDeg <= 170; angleDeg += 10) {
    Real angleRad = angleDeg * DEG_TO_RAD;

    Vector3 a(1.5, 0.0, 0.0);
    Vector3 b(0.0, 0.0, 0.0);
    Vector3 c(1.5 * cos(angleRad), 1.5 * sin(angleRad), 0.0);

    Vector3 aGrad, bGrad, cGrad;
    Real angle = angleGradient(a, b, c, aGrad, bGrad, cGrad);

    checkGradientsValid(aGrad, bGrad, cGrad);
    EXPECT_NEAR(angle, angleRad, 1e-6);
    compareWithNumerical(a, b, c);
  }
}

TEST_F(AngleGradientTest, ThreeDimensionalAngle)
{
  Vector3 a(1.0, 0.5, 0.3);
  Vector3 b(0.2, -0.1, 0.5);
  Vector3 c(-0.3, 0.8, -0.2);

  Vector3 aGrad, bGrad, cGrad;
  angleGradient(a, b, c, aGrad, bGrad, cGrad);

  checkGradientsValid(aGrad, bGrad, cGrad);
  compareWithNumerical(a, b, c);
}

TEST_F(AngleGradientTest, VeryShortBondLength)
{
  Vector3 a(1e-4, 0.0, 0.0);
  Vector3 b(0.0, 0.0, 0.0);
  Vector3 c(0.0, 1.0, 0.0);

  Vector3 aGrad, bGrad, cGrad;
  angleGradient(a, b, c, aGrad, bGrad, cGrad);

  // Should handle gracefully without crashing
  checkGradientsValid(aGrad, bGrad, cGrad);
}

TEST_F(AngleGradientTest, GradientsSumToZero)
{
  Vector3 a(1.5, 0.3, -0.2);
  Vector3 b(0.0, 0.0, 0.0);
  Vector3 c(-0.5, 1.2, 0.8);

  Vector3 aGrad, bGrad, cGrad;
  angleGradient(a, b, c, aGrad, bGrad, cGrad);

  // Gradients should approximately sum to zero (translation invariance)
  Vector3 sum = aGrad + bGrad + cGrad;
  EXPECT_NEAR(sum.norm(), 0.0, 1e-5);
}

// Dihedral Gradient Tests

TEST_F(DihedralGradientTest, StandardDihedral0Degrees)
{
  Vector3 i(1.0, 0.0, 0.0);
  Vector3 j(0.0, 0.0, 0.0);
  Vector3 k(0.0, 1.0, 0.0);
  Vector3 l(0.0, 1.0, 1.0);

  Vector3 iGrad, jGrad, kGrad, lGrad;
  Real phi = dihedralGradient(i, j, k, l, iGrad, jGrad, kGrad, lGrad);

  EXPECT_NEAR(phi, 0.0, 1e-6);
  checkGradientsValid(iGrad, jGrad, kGrad, lGrad);
  compareWithNumerical(i, j, k, l);
}

TEST_F(DihedralGradientTest, StandardDihedral90Degrees)
{
  Vector3 i(1.0, 0.0, 0.0);
  Vector3 j(0.0, 0.0, 0.0);
  Vector3 k(0.0, 1.0, 0.0);
  Vector3 l(-1.0, 1.0, 0.0);

  Vector3 iGrad, jGrad, kGrad, lGrad;
  Real phi = dihedralGradient(i, j, k, l, iGrad, jGrad, kGrad, lGrad);

  EXPECT_NEAR(std::abs(phi), M_PI / 2, 1e-5);
  checkGradientsValid(iGrad, jGrad, kGrad, lGrad);
  compareWithNumerical(i, j, k, l);
}

TEST_F(DihedralGradientTest, StandardDihedral180Degrees)
{
  Vector3 i(1.0, 0.0, 0.0);
  Vector3 j(0.0, 0.0, 0.0);
  Vector3 k(0.0, 1.0, 0.0);
  Vector3 l(0.0, 1.0, -1.0);

  Vector3 iGrad, jGrad, kGrad, lGrad;
  Real phi = dihedralGradient(i, j, k, l, iGrad, jGrad, kGrad, lGrad);

  EXPECT_NEAR(std::abs(phi), M_PI, 1e-5);
  checkGradientsValid(iGrad, jGrad, kGrad, lGrad);
}

TEST_F(DihedralGradientTest, StandardDihedralMinus90Degrees)
{
  Vector3 i(1.0, 0.0, 0.0);
  Vector3 j(0.0, 0.0, 0.0);
  Vector3 k(0.0, 1.0, 0.0);
  Vector3 l(1.0, 1.0, 0.0);

  Vector3 iGrad, jGrad, kGrad, lGrad;
  Real phi = dihedralGradient(i, j, k, l, iGrad, jGrad, kGrad, lGrad);

  EXPECT_NEAR(std::abs(phi), M_PI / 2, 1e-5);
  checkGradientsValid(iGrad, jGrad, kGrad, lGrad);
  compareWithNumerical(i, j, k, l);
}

TEST_F(DihedralGradientTest, RangeOfDihedrals)
{
  // Test dihedrals from -180 to 180 degrees in 30 degree increments
  for (int angleDeg = -180; angleDeg <= 180; angleDeg += 30) {
    Real angleRad = angleDeg * DEG_TO_RAD;

    Vector3 i(1.5, 0.0, 0.0);
    Vector3 j(0.0, 0.0, 0.0);
    Vector3 k(0.0, 1.5, 0.0);
    Vector3 l(1.5 * sin(angleRad), 1.5, 1.5 * cos(angleRad));

    Vector3 iGrad, jGrad, kGrad, lGrad;
    Real phi = dihedralGradient(i, j, k, l, iGrad, jGrad, kGrad, lGrad);

    checkGradientsValid(iGrad, jGrad, kGrad, lGrad);
    EXPECT_NEAR(phi, angleRad, 1e-5);
    compareWithNumerical(i, j, k, l);
  }
}

TEST_F(DihedralGradientTest, VaryingBondLengths)
{
  std::vector<Real> bondLengths = { 0.5, 1.0, 1.5, 2.0, 3.0 };

  for (Real r1 : bondLengths) {
    for (Real r2 : bondLengths) {
      for (Real r3 : bondLengths) {
        Vector3 i(r1, 0.0, 0.0);
        Vector3 j(0.0, 0.0, 0.0);
        Vector3 k(0.0, r2, 0.0);
        Vector3 l(0.0, r2, r3);

        Vector3 iGrad, jGrad, kGrad, lGrad;
        dihedralGradient(i, j, k, l, iGrad, jGrad, kGrad, lGrad);

        checkGradientsValid(iGrad, jGrad, kGrad, lGrad);
        compareWithNumerical(i, j, k, l, 1e-3);
      }
    }
  }
}

TEST_F(DihedralGradientTest, NearLinearConfiguration)
{
  // Nearly linear i-j-k angle
  Vector3 i(1.0, 0.0, 0.0);
  Vector3 j(0.0, 0.0, 0.0);
  Vector3 k(-1.0, 0.01, 0.0);
  Vector3 l(-1.0, 0.01, 1.0);

  Vector3 iGrad, jGrad, kGrad, lGrad;
  dihedralGradient(i, j, k, l, iGrad, jGrad, kGrad, lGrad);

  checkGradientsValid(iGrad, jGrad, kGrad, lGrad);
}

TEST_F(DihedralGradientTest, ArbitraryConfiguration)
{
  Vector3 i(1.2, -0.5, 0.3);
  Vector3 j(0.1, 0.8, -0.2);
  Vector3 k(-0.7, 0.3, 1.1);
  Vector3 l(-1.3, -0.4, 0.9);

  Vector3 iGrad, jGrad, kGrad, lGrad;
  dihedralGradient(i, j, k, l, iGrad, jGrad, kGrad, lGrad);

  checkGradientsValid(iGrad, jGrad, kGrad, lGrad);
  compareWithNumerical(i, j, k, l, 1e-3);
}

TEST_F(DihedralGradientTest, VeryShortBondLength)
{
  Vector3 i(1e-4, 0.0, 0.0);
  Vector3 j(0.0, 0.0, 0.0);
  Vector3 k(0.0, 1.0, 0.0);
  Vector3 l(0.0, 1.0, 1.0);

  Vector3 iGrad, jGrad, kGrad, lGrad;
  dihedralGradient(i, j, k, l, iGrad, jGrad, kGrad, lGrad);

  // Should handle gracefully
  checkGradientsValid(iGrad, jGrad, kGrad, lGrad);
}

TEST_F(DihedralGradientTest, GradientsSumToZero)
{
  Vector3 i(1.5, 0.3, -0.2);
  Vector3 j(0.5, -0.1, 0.4);
  Vector3 k(-0.2, 0.8, 0.1);
  Vector3 l(-1.0, 1.2, -0.5);

  Vector3 iGrad, jGrad, kGrad, lGrad;
  dihedralGradient(i, j, k, l, iGrad, jGrad, kGrad, lGrad);

  // Gradients should approximately sum to zero (translation invariance)
  Vector3 sum = iGrad + jGrad + kGrad + lGrad;
  EXPECT_NEAR(sum.norm(), 0.0, 1e-5);
}

// Out-of-Plane Gradient Tests

TEST(OutOfPlaneGradientTest, BasicTest)
{
  Vector3 a(1.0, 0.0, 0.5);
  Vector3 b(0.0, 1.0, 0.0);
  Vector3 c(-1.0, 0.0, 0.0);
  Vector3 d(0.0, -1.0, 0.0);

  Vector3 aGrad, bGrad, cGrad, dGrad;
  Real angle = outOfPlaneGradient(a, b, c, d, aGrad, bGrad, cGrad, dGrad);

  // Currently returns 0
  EXPECT_EQ(angle, 0.0);
  EXPECT_FALSE(hasNaNOrInf(aGrad));
  EXPECT_FALSE(hasNaNOrInf(bGrad));
  EXPECT_FALSE(hasNaNOrInf(cGrad));
  EXPECT_FALSE(hasNaNOrInf(dGrad));
}

TEST(OutOfPlaneGradientTest, GradientsAreZero)
{
  Vector3 a(0.5, 0.5, 0.2);
  Vector3 b(1.0, 0.0, 0.0);
  Vector3 c(0.0, 1.0, 0.0);
  Vector3 d(0.0, 0.0, 1.0);

  Vector3 aGrad, bGrad, cGrad, dGrad;
  outOfPlaneGradient(a, b, c, d, aGrad, bGrad, cGrad, dGrad);

  EXPECT_EQ(aGrad.norm(), 0.0);
  EXPECT_EQ(bGrad.norm(), 0.0);
  EXPECT_EQ(cGrad.norm(), 0.0);
  EXPECT_EQ(dGrad.norm(), 0.0);
}

// Stress tests with extreme values

TEST(GradientStressTest, AngleWithLargeBondLengths)
{
  Vector3 a(1000.0, 0.0, 0.0);
  Vector3 b(0.0, 0.0, 0.0);
  Vector3 c(0.0, 1000.0, 0.0);

  Vector3 aGrad, bGrad, cGrad;
  Real angle = angleGradient(a, b, c, aGrad, bGrad, cGrad);

  EXPECT_FALSE(std::isnan(angle));
  EXPECT_FALSE(std::isinf(angle));
  EXPECT_FALSE(hasNaNOrInf(aGrad));
  EXPECT_FALSE(hasNaNOrInf(bGrad));
  EXPECT_FALSE(hasNaNOrInf(cGrad));
}

TEST(GradientStressTest, DihedralWithLargeBondLengths)
{
  Vector3 i(1000.0, 0.0, 0.0);
  Vector3 j(0.0, 0.0, 0.0);
  Vector3 k(0.0, 1000.0, 0.0);
  Vector3 l(0.0, 1000.0, 1000.0);

  Vector3 iGrad, jGrad, kGrad, lGrad;
  Real phi = dihedralGradient(i, j, k, l, iGrad, jGrad, kGrad, lGrad);

  EXPECT_FALSE(std::isnan(phi));
  EXPECT_FALSE(std::isinf(phi));
  EXPECT_FALSE(hasNaNOrInf(iGrad));
  EXPECT_FALSE(hasNaNOrInf(jGrad));
  EXPECT_FALSE(hasNaNOrInf(kGrad));
  EXPECT_FALSE(hasNaNOrInf(lGrad));
}

TEST(GradientStressTest, AngleNearCollinear)
{
  // Test multiple configurations near 180 degrees
  for (Real offset = 1e-6; offset < 0.1; offset *= 10) {
    Vector3 a(1.0, 0.0, 0.0);
    Vector3 b(0.0, 0.0, 0.0);
    Vector3 c(-1.0, offset, 0.0);

    Vector3 aGrad, bGrad, cGrad;
    Real angle = angleGradient(a, b, c, aGrad, bGrad, cGrad);

    EXPECT_FALSE(std::isnan(angle));
    EXPECT_FALSE(std::isinf(angle));
    EXPECT_FALSE(hasNaNOrInf(aGrad));
    EXPECT_FALSE(hasNaNOrInf(bGrad));
    EXPECT_FALSE(hasNaNOrInf(cGrad));
  }
}
