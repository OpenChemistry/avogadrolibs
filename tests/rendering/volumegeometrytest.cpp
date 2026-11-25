/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/cube.h>
#include <avogadro/rendering/volumegeometry.h>

#include <limits>
#include <vector>

using Avogadro::Vector3;
using Avogadro::Vector3i;
using Avogadro::Vector3ub;
using Avogadro::Core::Cube;
using Avogadro::Rendering::VolumeGeometry;

TEST(VolumeGeometryTest, defaultsAndPropertiesWithoutGLContext)
{
  VolumeGeometry volume;
  EXPECT_EQ(volume.cube(), nullptr);
  EXPECT_EQ(volume.positiveColor(), Vector3ub(255, 0, 0));
  EXPECT_EQ(volume.negativeColor(), Vector3ub(0, 0, 255));

  volume.setPositiveColor(Vector3ub(10, 200, 30));
  volume.setNegativeColor(Vector3ub(200, 100, 40));
  EXPECT_EQ(volume.positiveColor(), Vector3ub(10, 200, 30));
  EXPECT_EQ(volume.negativeColor(), Vector3ub(200, 100, 40));

  Cube cube;
  cube.setLimits(Vector3(-1.0, -1.0, -1.0), Vector3(1.0, 1.0, 1.0),
                 Vector3i(4, 4, 4));
  std::vector<float> data(4 * 4 * 4, 0.5f);
  cube.setData(data);

  volume.setCube(cube);
  EXPECT_EQ(volume.cube(), &cube);

  volume.clear();
  EXPECT_EQ(volume.cube(), nullptr);
}

TEST(VolumeGeometryTest, copyAndAssignSafeWithoutGLContext)
{
  Cube cube;
  cube.setLimits(Vector3(-2.0, -2.0, -2.0), Vector3(2.0, 2.0, 2.0),
                 Vector3i(4, 4, 4));
  std::vector<float> data(4 * 4 * 4, 1.0f);
  cube.setData(data);

  VolumeGeometry original;
  original.setCube(cube);
  original.setPositiveColor(Vector3ub(250, 10, 20));
  original.setNegativeColor(Vector3ub(20, 30, 240));

  VolumeGeometry copy(original);
  EXPECT_EQ(copy.cube(), &cube);
  EXPECT_EQ(copy.positiveColor(), Vector3ub(250, 10, 20));
  EXPECT_EQ(copy.negativeColor(), Vector3ub(20, 30, 240));

  VolumeGeometry assigned;
  assigned = copy;
  EXPECT_EQ(assigned.cube(), &cube);
  assigned.setPositiveColor(Vector3ub(1, 2, 3));
  EXPECT_EQ(original.positiveColor(), Vector3ub(250, 10, 20));
}

TEST(VolumeGeometryTest, alphaScaleWithoutGLContext)
{
  VolumeGeometry volume;
  EXPECT_FLOAT_EQ(volume.alphaScale(), 1.0f);

  volume.setAlphaScale(2.5f);
  EXPECT_FLOAT_EQ(volume.alphaScale(), 2.5f);

  // NaN is ignored; negative and -inf clamp to zero.
  volume.setAlphaScale(std::numeric_limits<float>::quiet_NaN());
  EXPECT_FLOAT_EQ(volume.alphaScale(), 2.5f);
  volume.setAlphaScale(-3.0f);
  EXPECT_FLOAT_EQ(volume.alphaScale(), 0.0f);
  volume.setAlphaScale(4.0f);
  volume.setAlphaScale(-std::numeric_limits<float>::infinity());
  EXPECT_FLOAT_EQ(volume.alphaScale(), 0.0f);

  volume.setAlphaScale(7.0f);
  VolumeGeometry copy(volume);
  EXPECT_FLOAT_EQ(copy.alphaScale(), 7.0f);

  VolumeGeometry assigned;
  assigned = volume;
  EXPECT_FLOAT_EQ(assigned.alphaScale(), 7.0f);
  assigned.setAlphaScale(0.5f);
  EXPECT_FLOAT_EQ(volume.alphaScale(), 7.0f);
}
