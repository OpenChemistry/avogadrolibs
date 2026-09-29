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
