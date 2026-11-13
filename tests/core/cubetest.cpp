/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/molecule.h>

#include <cmath>
#include <limits>
#include <vector>

using Avogadro::Matrix3;
using Avogadro::Vector3;
using Avogadro::Vector3i;
using Avogadro::Core::Cube;
using Avogadro::Core::Molecule;

TEST(CubeTest, initialize)
{
  Cube cube;
  EXPECT_EQ(cube.dimensions(), Vector3i::Zero());
}

TEST(CubeTest, name)
{
  Cube cube;
  cube.setName("test");
  EXPECT_EQ(cube.name(), "test");
}

TEST(CubeTest, limits)
{
  Cube cube;
  cube.setLimits(Vector3(0.0, 0.0, 0.0), Vector3(1.0, 1.0, 1.0),
                 Vector3i(10, 10, 10));
  EXPECT_EQ(cube.data()->size(), 1000);
  for (int i = 0; i < 3; ++i) {
    EXPECT_DOUBLE_EQ(cube.min()[i], 0.0);
    EXPECT_DOUBLE_EQ(cube.max()[i], 1.0);
    EXPECT_EQ(cube.dimensions()[i], 10);
  }

  Cube cube2;
  cube2.setLimits(cube);
  for (int i = 0; i < 3; ++i) {
    EXPECT_DOUBLE_EQ(cube2.min()[i], 0.0);
    EXPECT_DOUBLE_EQ(cube2.max()[i], 1.0);
    EXPECT_EQ(cube2.dimensions()[i], 10);
  }
  EXPECT_EQ(cube.data()->size(), 1000);
}

TEST(CubeTest, value)
{
  Cube cube;
  cube.setLimits(Vector3(0.0, 0.0, 0.0), Vector3(1.0, 1.0, 1.0),
                 Vector3i(10, 10, 10));
  cube.setValue(0, 0, 0, 5.0);
  cube.setValue(0, 0, 1, 50.0);

  EXPECT_DOUBLE_EQ(cube.value(0, 0, 0), 5.0);
  EXPECT_DOUBLE_EQ(cube.value(0, 0, 1), 50.0);
}

TEST(CubeTest, minmax)
{
  Cube cube;
  cube.setLimits(Vector3(0.0, 0.0, 0.0), Vector3(1.0, 1.0, 1.0),
                 Vector3i(10, 10, 10));
  cube.setValue(0, 0, 0, 5.0);
  cube.setValue(0, 0, 1, 50.0);

  EXPECT_DOUBLE_EQ(cube.minValue(), 0.0);
  EXPECT_DOUBLE_EQ(cube.maxValue(), 50.0);
}

TEST(CubeTest, index)
{
  Cube cube;
  cube.setLimits(Vector3(0.0, 0.0, 0.0), Vector3(1.0, 1.0, 1.0),
                 Vector3i(10, 10, 10));
  EXPECT_EQ(cube.closestIndex(Vector3(0.0, 0.0, 0.0)), 0);
  EXPECT_EQ(cube.closestIndex(Vector3(1.0, 0.0, 0.0)), 900);
  EXPECT_EQ(cube.closestIndex(Vector3(0.0, 1.0, 0.0)), 90);
  EXPECT_EQ(cube.closestIndex(Vector3(0.0, 0.0, 1.0)), 9);
  EXPECT_EQ(cube.closestIndex(Vector3(1.0, 1.0, 1.0)), 999);
}

TEST(CubeTest, position)
{
  Cube cube;
  cube.setLimits(Vector3(0.0, 0.0, 0.0), Vector3(1.0, 1.0, 1.0),
                 Vector3i(10, 10, 10));
  for (int i = 0; i < 3; ++i)
    EXPECT_DOUBLE_EQ(cube.position(0)[i], 0.0);
  for (int i = 0; i < 3; ++i)
    EXPECT_DOUBLE_EQ(cube.position(999)[i], 1.0);
}

namespace {

// A valid 3x4x5 cube with distinct values, so any change a rejected
// setLimits() call makes to it is visible.
void makeReferenceCube(Cube& cube)
{
  ASSERT_TRUE(cube.setLimits(Vector3(-1.0, -2.0, -3.0), Vector3(1.0, 2.0, 3.0),
                             Vector3i(3, 4, 5)));
  std::vector<float> values(3 * 4 * 5);
  for (size_t i = 0; i < values.size(); ++i)
    values[i] = static_cast<float>(i);
  ASSERT_TRUE(cube.setData(values));
}

void expectReferenceCube(Cube& cube)
{
  EXPECT_EQ(cube.dimensions(), Vector3i(3, 4, 5));
  EXPECT_EQ(cube.min(), Vector3(-1.0, -2.0, -3.0));
  EXPECT_EQ(cube.max(), Vector3(1.0, 2.0, 3.0));
  EXPECT_EQ(cube.spacing(), Vector3(1.0, 4.0 / 3.0, 1.5));
  ASSERT_EQ(cube.data()->size(), 60u);
  for (size_t i = 0; i < cube.data()->size(); ++i)
    EXPECT_EQ((*cube.data())[i], static_cast<float>(i));
}

void expectEmptyCube(Cube& cube)
{
  EXPECT_EQ(cube.dimensions(), Vector3i(0, 0, 0));
  EXPECT_EQ(cube.spacing(), Vector3(0.0, 0.0, 0.0));
  EXPECT_TRUE(cube.data()->empty());
}

} // namespace

// Regression test: setLimits(min, max, points) divided by points - 1, so a
// dimension of one gave an infinite or NaN spacing and zero or negative
// dimensions a bogus allocation.
TEST(CubeTest, limitsRejectBadPointCounts)
{
  const Vector3 min(0.0, 0.0, 0.0), max(1.0, 1.0, 1.0);
  const Vector3i bad[] = { Vector3i(0, 10, 10),  Vector3i(10, 0, 10),
                           Vector3i(10, 10, 0),  Vector3i(1, 10, 10),
                           Vector3i(10, 1, 10),  Vector3i(10, 10, 1),
                           Vector3i(1, 1, 1),    Vector3i(-1, 10, 10),
                           Vector3i(10, 10, -5), Vector3i(-2, -2, -2) };
  for (const auto& points : bad) {
    Cube fresh;
    EXPECT_FALSE(fresh.setLimits(min, max, points)) << points.transpose();
    expectEmptyCube(fresh);

    Cube cube;
    makeReferenceCube(cube);
    EXPECT_FALSE(cube.setLimits(min, max, points)) << points.transpose();
    expectReferenceCube(cube);
  }

  // More points than an int can index.
  Cube huge;
  EXPECT_FALSE(huge.setLimits(min, max, Vector3i(2000, 2000, 2000)));
  expectEmptyCube(huge);

  // Non-finite corners.
  const double inf = std::numeric_limits<double>::infinity();
  Cube infinite;
  EXPECT_FALSE(
    infinite.setLimits(min, Vector3(inf, 1.0, 1.0), Vector3i(10, 10, 10)));
  expectEmptyCube(infinite);

  // The smallest valid grid: two points per axis.
  Cube cube;
  EXPECT_TRUE(cube.setLimits(min, max, Vector3i(2, 2, 2)));
  EXPECT_EQ(cube.spacing(), Vector3(1.0, 1.0, 1.0));
  EXPECT_EQ(cube.data()->size(), 8u);
}

TEST(CubeTest, limitsFromSpacingRejectBadInput)
{
  const Vector3 min(0.0, 0.0, 0.0);
  const double nan = std::numeric_limits<double>::quiet_NaN();
  const double inf = std::numeric_limits<double>::infinity();

  // Dimensions: one point is fine when the spacing is given, zero or
  // negative is not.
  const Vector3i badDims[] = { Vector3i(0, 4, 4), Vector3i(4, 0, 4),
                               Vector3i(4, 4, 0), Vector3i(-1, 4, 4),
                               Vector3i(4, 4, -3) };
  for (const auto& dim : badDims) {
    Cube cube;
    makeReferenceCube(cube);
    EXPECT_FALSE(cube.setLimits(min, dim, 0.5f)) << dim.transpose();
    EXPECT_FALSE(cube.setLimits(min, dim, Vector3(0.5, 0.5, 0.5)))
      << dim.transpose();
    expectReferenceCube(cube);
  }

  // Spacing: must be positive and finite on every axis.
  const Vector3 badSpacing[] = { Vector3(0.0, 0.5, 0.5),
                                 Vector3(0.5, -0.5, 0.5),
                                 Vector3(0.5, 0.5, nan),
                                 Vector3(inf, 0.5, 0.5) };
  for (const auto& spacing : badSpacing) {
    Cube cube;
    makeReferenceCube(cube);
    EXPECT_FALSE(cube.setLimits(min, Vector3i(4, 4, 4), spacing))
      << spacing.transpose();
    expectReferenceCube(cube);
  }
  for (float spacing : { 0.0f, -1.0f, std::numeric_limits<float>::quiet_NaN(),
                         std::numeric_limits<float>::infinity() }) {
    Cube cube;
    makeReferenceCube(cube);
    EXPECT_FALSE(cube.setLimits(min, Vector3i(4, 4, 4), spacing)) << spacing;
    EXPECT_FALSE(cube.setLimits(min, Vector3(1.0, 1.0, 1.0), spacing))
      << spacing;
    expectReferenceCube(cube);
  }

  // min/max with a spacing: a grid under two points per axis is rejected,
  // as is one too large to count in an int.
  Cube cube;
  makeReferenceCube(cube);
  EXPECT_FALSE(cube.setLimits(min, Vector3(1.0, 1.0, 1.0), 0.75f));
  EXPECT_FALSE(cube.setLimits(min, Vector3(1.0, 1.0, 1.0), 1e-10f));
  EXPECT_FALSE(cube.setLimits(Vector3(1.0, 1.0, 1.0), min, 0.1f));
  expectReferenceCube(cube);

  // Copying the limits of an empty cube is rejected.
  Cube empty;
  EXPECT_FALSE(cube.setLimits(empty));
  expectReferenceCube(cube);

  // Valid spacing-based calls, including a single-point axis.
  Cube slab;
  EXPECT_TRUE(slab.setLimits(min, Vector3i(4, 4, 1), Vector3(0.5, 0.5, 0.5)));
  EXPECT_EQ(slab.dimensions(), Vector3i(4, 4, 1));
  EXPECT_EQ(slab.max(), Vector3(1.5, 1.5, 0.0));
  EXPECT_EQ(slab.data()->size(), 16u);

  Cube copy;
  EXPECT_TRUE(copy.setLimits(slab));
  EXPECT_EQ(copy.dimensions(), Vector3i(4, 4, 1));
  EXPECT_EQ(copy.data()->size(), 16u);

  // Existing behaviour: points = floor(delta / spacing).
  Cube grid;
  EXPECT_TRUE(grid.setLimits(min, Vector3(1.0, 2.0, 3.0), 0.5f));
  EXPECT_EQ(grid.dimensions(), Vector3i(2, 4, 6));
}

TEST(CubeTest, limitsFromMolecule)
{
  Molecule mol;
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(1.0, 0.0, 0.0));

  Cube cube;
  EXPECT_TRUE(cube.setLimits(mol, 0.5f, 2.0f));
  EXPECT_EQ(cube.min(), Vector3(-2.0, -2.0, -2.0));
  EXPECT_EQ(cube.dimensions(), Vector3i(10, 8, 8));

  // No padding and a flat molecule: zero extent along y and z.
  Cube flat;
  EXPECT_FALSE(flat.setLimits(mol, 0.5f, 0.0f));
  expectEmptyCube(flat);
}

// computeGradient() must return +grad f (pointing toward increasing values),
// including the one-sided differences on the cube boundary.
TEST(CubeTest, computeGradientLinearField)
{
  const float a = 2.0f, b = -3.0f, c = 0.5f;
  Cube cube;
  ASSERT_TRUE(cube.setLimits(Vector3(-1.0, 0.5, 2.0), Vector3i(5, 6, 7),
                             Vector3(0.3, 0.4, 0.5)));
  const Vector3i dim = cube.dimensions();
  for (int i = 0; i < dim.x(); ++i)
    for (int j = 0; j < dim.y(); ++j)
      for (int k = 0; k < dim.z(); ++k) {
        Vector3 pos = cube.position(i * dim.y() * dim.z() + j * dim.z() + k);
        cube.setValue(i, j, k,
                      a * static_cast<float>(pos.x()) +
                        b * static_cast<float>(pos.y()) +
                        c * static_cast<float>(pos.z()));
      }

  const int pts[][3] = { { 2, 3, 3 }, { 0, 0, 0 }, { 4, 5, 6 },
                         { 0, 3, 6 }, { 4, 0, 3 }, { 2, 5, 0 } };
  for (const auto& p : pts) {
    auto g = cube.computeGradient(p[0], p[1], p[2]);
    EXPECT_NEAR(g[0], a, 1.0e-3) << p[0] << " " << p[1] << " " << p[2];
    EXPECT_NEAR(g[1], b, 1.0e-3) << p[0] << " " << p[1] << " " << p[2];
    EXPECT_NEAR(g[2], c, 1.0e-3) << p[0] << " " << p[1] << " " << p[2];
  }
}

namespace {

// Step vectors (columns) of a triclinic-looking grid.
Matrix3 skewedSteps()
{
  Matrix3 steps;
  steps << 0.30, 0.11, -0.07, //
    0.02, 0.25, 0.05,         //
    -0.03, 0.04, 0.28;
  return steps;
}

float linearFunction(const Vector3& r)
{
  return static_cast<float>(1.5 * r.x() - 0.75 * r.y() + 2.0 * r.z() + 0.25);
}

} // namespace

TEST(CubeTest, stepsOfAxisAlignedGrid)
{
  Cube cube;
  ASSERT_TRUE(cube.setLimits(Vector3(1.0, 2.0, 3.0), Vector3i(3, 4, 5),
                             Vector3(0.5, 0.25, 0.125)));
  EXPECT_TRUE(cube.isAxisAligned());
  EXPECT_EQ(cube.steps(), Matrix3(Vector3(0.5, 0.25, 0.125).asDiagonal()));
  EXPECT_EQ(cube.spacing(), Vector3(0.5, 0.25, 0.125));
  EXPECT_EQ(cube.max(), Vector3(2.0, 2.75, 3.5));
  Vector3 lo, hi;
  cube.boundingBox(lo, hi);
  EXPECT_EQ(lo, cube.min());
  EXPECT_EQ(hi, cube.max());
}

TEST(CubeTest, skewedPositionAndIndexRoundTrip)
{
  const Matrix3 steps = skewedSteps();
  const Vector3 origin(-1.0, 0.5, 2.0);
  const Vector3i dim(5, 6, 7);
  Cube cube;
  ASSERT_TRUE(cube.setLimits(origin, dim, steps));
  EXPECT_FALSE(cube.isAxisAligned());
  EXPECT_EQ(cube.steps(), steps);
  EXPECT_EQ(cube.min(), origin);
  EXPECT_TRUE(cube.max().isApprox(origin + steps * Vector3(4, 5, 6), 1e-12));
  for (int d = 0; d < 3; ++d)
    EXPECT_NEAR(cube.spacing()(d), steps.col(d).norm(), 1e-14);
  EXPECT_EQ(cube.data()->size(), static_cast<size_t>(5 * 6 * 7));

  // Bounding box encloses all eight corners and touches them.
  Vector3 lo, hi;
  cube.boundingBox(lo, hi);
  Vector3 expectLo = origin, expectHi = origin;
  for (int c = 0; c < 8; ++c) {
    const Vector3 corner =
      origin +
      steps * Vector3((c & 1) ? 4 : 0, (c & 2) ? 5 : 0, (c & 4) ? 6 : 0);
    expectLo = expectLo.cwiseMin(corner);
    expectHi = expectHi.cwiseMax(corner);
  }
  EXPECT_TRUE(lo.isApprox(expectLo, 1e-12));
  EXPECT_TRUE(hi.isApprox(expectHi, 1e-12));

  for (int i = 0; i < dim.x(); ++i)
    for (int j = 0; j < dim.y(); ++j)
      for (int k = 0; k < dim.z(); ++k) {
        const unsigned int index =
          static_cast<unsigned int>(i * dim.y() * dim.z() + j * dim.z() + k);
        const Vector3 pos = cube.position(index);
        EXPECT_TRUE(pos.isApprox(origin + steps * Vector3(i, j, k), 1e-12));
        // A little inside the cell the index is the cell's own.
        const Vector3 inCell = pos + steps * Vector3(0.3, 0.3, 0.3);
        EXPECT_EQ(cube.indexVector(inCell), Vector3i(i, j, k));
      }
  // Positions outside the grid never give an index outside it.
  const unsigned int far = cube.closestIndex(Vector3(1.0e6, -1.0e6, 1.0e6));
  EXPECT_LT(far, cube.data()->size());
  const double nan = std::numeric_limits<double>::quiet_NaN();
  EXPECT_LT(cube.closestIndex(Vector3(nan, 0, 0)), cube.data()->size());
}

TEST(CubeTest, skewedValueReproducesLinearFunction)
{
  Cube cube;
  const Vector3 origin(0.3, -0.2, 0.1);
  const Vector3i dim(6, 7, 8);
  ASSERT_TRUE(cube.setLimits(origin, dim, skewedSteps()));
  for (unsigned int i = 0; i < cube.data()->size(); ++i)
    cube.setValue(i, linearFunction(cube.position(i)));

  // Trilinear interpolation is exact for a linear function.
  const Vector3 fractions[] = { { 0.4, 0.7, 0.2 },
                                { 3.5, 1.25, 4.75 },
                                { 4.99, 5.01, 6.5 },
                                { 0.0, 0.0, 0.0 } };
  for (const Vector3& u : fractions) {
    const Vector3 pos = origin + skewedSteps() * u;
    EXPECT_NEAR(cube.value(pos), linearFunction(pos), 2.0e-5);
    EXPECT_NEAR(cube.valuef(pos.cast<float>()), linearFunction(pos), 2.0e-4);
  }
  // Well outside the grid there is nothing, and nothing odd happens.
  EXPECT_EQ(cube.value(Vector3(100.0, 100.0, 100.0)), 0.0f);
  EXPECT_EQ(cube.value(Vector3(std::numeric_limits<double>::quiet_NaN(), 0, 0)),
            0.0f);
}

// computeGradient() is +grad f (toward increasing values).
TEST(CubeTest, skewedGradientOfLinearFunction)
{
  Cube cube;
  ASSERT_TRUE(
    cube.setLimits(Vector3(0.3, -0.2, 0.1), Vector3i(6, 7, 8), skewedSteps()));
  for (unsigned int i = 0; i < cube.data()->size(); ++i)
    cube.setValue(i, linearFunction(cube.position(i)));

  // Corners, edges, faces and interior all use different differences.
  const int pts[][3] = { { 0, 0, 0 }, { 5, 6, 7 }, { 2, 3, 4 }, { 0, 3, 7 },
                         { 5, 0, 4 }, { 2, 6, 0 }, { 3, 3, 3 } };
  for (const auto& p : pts) {
    const auto g = cube.computeGradient(p[0], p[1], p[2]);
    EXPECT_NEAR(g[0], 1.5, 2.0e-3) << p[0] << " " << p[1] << " " << p[2];
    EXPECT_NEAR(g[1], -0.75, 2.0e-3) << p[0] << " " << p[1] << " " << p[2];
    EXPECT_NEAR(g[2], 2.0, 2.0e-3) << p[0] << " " << p[1] << " " << p[2];
  }
  // Out-of-range points have no gradient rather than a wild read.
  const auto none = cube.computeGradient(-1, 0, 0);
  EXPECT_EQ(none[0], 0.0f);
}

TEST(CubeTest, leftHandedStepsAreAccepted)
{
  Matrix3 steps = skewedSteps();
  steps.col(0) *= -1.0;
  ASSERT_LT(steps.determinant(), 0.0);
  Cube cube;
  ASSERT_TRUE(cube.setLimits(Vector3(0, 0, 0), Vector3i(4, 4, 4), steps));
  for (unsigned int i = 0; i < cube.data()->size(); ++i)
    cube.setValue(i, linearFunction(cube.position(i)));
  const auto g = cube.computeGradient(1, 2, 1);
  EXPECT_NEAR(g[0], 1.5, 2.0e-3);
  EXPECT_NEAR(g[1], -0.75, 2.0e-3);
  EXPECT_NEAR(g[2], 2.0, 2.0e-3);
}

TEST(CubeTest, invalidStepsAreRejected)
{
  Cube cube;
  const Vector3 origin(1.0, 2.0, 3.0);
  ASSERT_TRUE(cube.setLimits(origin, Vector3i(2, 2, 2), skewedSteps()));
  const Matrix3 good = cube.steps();

  // Singular: two parallel columns, and a zero column.
  Matrix3 parallel = skewedSteps();
  parallel.col(1) = 2.0 * parallel.col(0);
  EXPECT_FALSE(cube.setLimits(origin, Vector3i(3, 3, 3), parallel));
  Matrix3 zero = skewedSteps();
  zero.col(2).setZero();
  EXPECT_FALSE(cube.setLimits(origin, Vector3i(3, 3, 3), zero));
  // Nearly singular for its size, whatever the unit.
  EXPECT_FALSE(cube.setLimits(origin, Vector3i(3, 3, 3), parallel * 1.0e6));
  // Not finite.
  Matrix3 bad = skewedSteps();
  bad(1, 1) = std::numeric_limits<double>::quiet_NaN();
  EXPECT_FALSE(cube.setLimits(origin, Vector3i(3, 3, 3), bad));
  bad = skewedSteps();
  bad(0, 2) = std::numeric_limits<double>::infinity();
  EXPECT_FALSE(cube.setLimits(origin, Vector3i(3, 3, 3), bad));
  EXPECT_FALSE(
    cube.setLimits(Vector3(std::numeric_limits<double>::quiet_NaN(), 0, 0),
                   Vector3i(3, 3, 3), skewedSteps()));
  // Too few points.
  EXPECT_FALSE(cube.setLimits(origin, Vector3i(0, 3, 3), skewedSteps()));

  // The cube is as it was.
  EXPECT_EQ(cube.dimensions(), Vector3i(2, 2, 2));
  EXPECT_EQ(cube.steps(), good);
  EXPECT_EQ(cube.min(), origin);
}

TEST(CubeTest, copyingLimitsKeepsSteps)
{
  Cube a;
  ASSERT_TRUE(a.setLimits(Vector3(1, 2, 3), Vector3i(3, 3, 3), skewedSteps()));
  Cube b;
  ASSERT_TRUE(b.setLimits(a));
  EXPECT_FALSE(b.isAxisAligned());
  EXPECT_EQ(b.steps(), a.steps());
  EXPECT_EQ(b.max(), a.max());
  EXPECT_EQ(b.position(13), a.position(13));
}
