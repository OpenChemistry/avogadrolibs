/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <vibrationframes.h>

#include <cmath>

using Avogadro::Vector3;
using Avogadro::Core::Array;
using Avogadro::QtPlugins::nearestVibrationFrame;
using Avogadro::QtPlugins::vibrationFrames;

namespace {

constexpr double pi = 3.14159265358979323846;

// Array's brace initialization picks the iterator constructor for two
// Vector3 values, so build the arrays explicitly.
Array<Vector3> pair(const Vector3& a, const Vector3& b)
{
  Array<Vector3> result;
  result.push_back(a);
  result.push_back(b);
  return result;
}

Array<Vector3> restGeometry()
{
  return pair(Vector3(0.0, 0.0, 0.0), Vector3(1.0, 0.5, -0.25));
}

Array<Vector3> mode()
{
  return pair(Vector3(0.1, 0.0, 0.0), Vector3(-0.2, 0.3, 0.4));
}

} // namespace

TEST(VibrationsCommandTest, FramesFollowSineWithRestFirst)
{
  const int count = 8;
  const auto rest = restGeometry();
  const auto lx = mode();
  const auto frames = vibrationFrames(rest, lx, 2.0, count);
  ASSERT_EQ(frames.size(), static_cast<size_t>(count));

  // Frame 0 is the rest geometry, and the last frame is not a second copy.
  for (size_t i = 0; i < rest.size(); ++i)
    EXPECT_EQ(frames[0][i], rest[i]);
  EXPECT_NE(frames[count - 1][1], rest[1]);

  for (int k = 0; k < count; ++k) {
    ASSERT_EQ(frames[k].size(), rest.size());
    const double s = std::sin(2.0 * pi * k / count);
    for (size_t i = 0; i < rest.size(); ++i)
      EXPECT_NEAR((frames[k][i] - (rest[i] + lx[i] * 2.0 * s)).norm(), 0.0,
                  1e-12);
  }
}

TEST(VibrationsCommandTest, FramesScaleLinearlyWithPeak)
{
  const auto rest = restGeometry();
  const auto lx = mode();
  const auto one = vibrationFrames(rest, lx, 1.0, 12);
  const auto three = vibrationFrames(rest, lx, 3.0, 12);
  ASSERT_EQ(one.size(), three.size());
  for (size_t k = 0; k < one.size(); ++k)
    for (size_t i = 0; i < rest.size(); ++i)
      EXPECT_NEAR(
        ((three[k][i] - rest[i]) - 3.0 * (one[k][i] - rest[i])).norm(), 0.0,
        1e-12);
}

TEST(VibrationsCommandTest, FramesRejectBadInput)
{
  const auto rest = restGeometry();
  const auto lx = mode();
  EXPECT_TRUE(vibrationFrames(rest, lx, 1.0, 0).empty());
  EXPECT_TRUE(vibrationFrames(rest, lx, 1.0, -4).empty());
  EXPECT_TRUE(
    vibrationFrames(Array<Vector3>(), Array<Vector3>(), 1.0, 8).empty());
  Array<Vector3> shortMode;
  shortMode.push_back(Vector3(1.0, 0.0, 0.0));
  EXPECT_TRUE(vibrationFrames(rest, shortMode, 1.0, 8).empty());
  EXPECT_EQ(vibrationFrames(rest, lx, 1.0, 1).size(), 1u);
}

TEST(VibrationsCommandTest, NearestFrame)
{
  EXPECT_EQ(nearestVibrationFrame({ 5, 9 }, 0), 5);
  EXPECT_EQ(nearestVibrationFrame({ 2, 3 }, 10), 3);
  EXPECT_EQ(nearestVibrationFrame({ 9, 2, 5 }, 4), 5);
  EXPECT_EQ(nearestVibrationFrame({ 2, 6 }, 4), 6); // tie goes later
  EXPECT_EQ(nearestVibrationFrame({ 6, 2 }, 4), 6);
  // The current frame is skipped.
  EXPECT_EQ(nearestVibrationFrame({ 1, 4 }, 4), 1);
  EXPECT_EQ(nearestVibrationFrame({ 4 }, 4), -1);
  EXPECT_EQ(nearestVibrationFrame({}, 4), -1);
}
