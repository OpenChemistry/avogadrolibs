/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/angletools.h>

#include <cmath>
#include <vector>

using Avogadro::bondAngle;
using Avogadro::calculateAngle;
using Avogadro::shiftValuesToWindow;
using Avogadro::unwrapPeriodicValues;

namespace {
const double tol = 1.0e-9;
} // namespace

TEST(AngleToolsTest, unwrapLeavesContinuousSeriesAlone)
{
  std::vector<double> values{ -90.0, -60.0, -30.0, 0.0, 30.0 };
  const std::vector<double> expected = values;

  unwrapPeriodicValues(values, 360.0);

  ASSERT_EQ(values.size(), expected.size());
  for (size_t i = 0; i < values.size(); ++i)
    EXPECT_NEAR(values[i], expected[i], tol);
}

TEST(AngleToolsTest, unwrapFollowsAScanPastTheWrap)
{
  // A torsion scan stepping by 30 degrees through 180: as measured, it jumps
  // from 180 to -150, which would draw a line right across the plot.
  std::vector<double> values{ 120.0, 150.0, 180.0, -150.0, -120.0 };

  unwrapPeriodicValues(values, 360.0);

  const std::vector<double> expected{ 120.0, 150.0, 180.0, 210.0, 240.0 };
  ASSERT_EQ(values.size(), expected.size());
  for (size_t i = 0; i < values.size(); ++i)
    EXPECT_NEAR(values[i], expected[i], tol);

  // Every step stays the size it was actually scanned.
  for (size_t i = 1; i < values.size(); ++i)
    EXPECT_NEAR(values[i] - values[i - 1], 30.0, tol);
}

TEST(AngleToolsTest, unwrapFollowsAScanDownwards)
{
  std::vector<double> values{ -120.0, -150.0, 180.0, 150.0, 120.0 };

  unwrapPeriodicValues(values, 360.0);

  for (size_t i = 1; i < values.size(); ++i)
    EXPECT_NEAR(values[i] - values[i - 1], -30.0, tol);
}

TEST(AngleToolsTest, unwrapIgnoresNonPositivePeriods)
{
  std::vector<double> values{ 120.0, -150.0 };
  unwrapPeriodicValues(values, 0.0);
  EXPECT_NEAR(values[1], -150.0, tol);

  unwrapPeriodicValues(values, -360.0);
  EXPECT_NEAR(values[1], -150.0, tol);
}

TEST(AngleToolsTest, unwrapHandlesEmptyAndSingleValues)
{
  std::vector<double> empty;
  unwrapPeriodicValues(empty, 360.0);
  EXPECT_TRUE(empty.empty());

  std::vector<double> single{ 42.0 };
  unwrapPeriodicValues(single, 360.0);
  ASSERT_EQ(single.size(), 1u);
  EXPECT_NEAR(single[0], 42.0, tol);
}

TEST(AngleToolsTest, shiftBringsAnUnwrappedScanBackIntoRange)
{
  // Unwrapping can leave the whole scan above the axis range.
  std::vector<double> values{ 380.0, 410.0, 440.0 };

  shiftValuesToWindow(values, 360.0, -180.0, 180.0);

  const std::vector<double> expected{ 20.0, 50.0, 80.0 };
  ASSERT_EQ(values.size(), expected.size());
  for (size_t i = 0; i < values.size(); ++i)
    EXPECT_NEAR(values[i], expected[i], tol);
}

TEST(AngleToolsTest, shiftKeepsTheSeriesContinuous)
{
  // A scan that legitimately spans more than one period must not be folded
  // back on itself; only a whole-period offset is allowed.
  std::vector<double> values{ 170.0, 200.0, 230.0, 260.0 };

  shiftValuesToWindow(values, 360.0, -180.0, 180.0);

  for (size_t i = 1; i < values.size(); ++i)
    EXPECT_NEAR(values[i] - values[i - 1], 30.0, tol);
}

TEST(AngleToolsTest, shiftPrefersTheWindowHoldingMostPoints)
{
  // Three of four points fit if shifted down by one period, one if not.
  std::vector<double> values{ 170.0, 190.0, 220.0, 250.0 };

  shiftValuesToWindow(values, 360.0, -180.0, 180.0);

  int inside = 0;
  for (double value : values)
    if (value >= -180.0 && value <= 180.0)
      ++inside;

  EXPECT_EQ(inside, 3);
}

TEST(AngleToolsTest, shiftIgnoresAnInvalidWindow)
{
  std::vector<double> values{ 380.0 };

  shiftValuesToWindow(values, 360.0, 180.0, -180.0);
  EXPECT_NEAR(values[0], 380.0, tol);

  shiftValuesToWindow(values, 0.0, -180.0, 180.0);
  EXPECT_NEAR(values[0], 380.0, tol);
}

TEST(AngleToolsTest, unwrapAndShiftRoundTripAFullScan)
{
  // A 0 to 360 scan in 30 degree steps, as it comes back from the geometry:
  // everything past 180 reads negative.
  std::vector<double> values;
  for (int step = 0; step <= 12; ++step) {
    double angle = step * 30.0;
    if (angle > 180.0)
      angle -= 360.0;
    values.push_back(angle);
  }

  unwrapPeriodicValues(values, 360.0);
  shiftValuesToWindow(values, 360.0, -180.0, 180.0);

  // Monotonic, evenly spaced, and covering one full turn.
  for (size_t i = 1; i < values.size(); ++i)
    EXPECT_NEAR(values[i] - values[i - 1], 30.0, tol);
  EXPECT_NEAR(values.back() - values.front(), 360.0, tol);
}

TEST(AngleToolsTest, helpersWorkOnFloatSeries)
{
  // The plot code carries floats, so the templates must instantiate for them.
  std::vector<float> values{ 170.0f, 200.0f };

  unwrapPeriodicValues(values, 360.0f);
  shiftValuesToWindow(values, 360.0f, -180.0f, 180.0f);

  EXPECT_NEAR(values[1] - values[0], 30.0f, 1.0e-4f);
}

TEST(AngleToolsTest, bondAngleOfCollinearBondsIsFinite)
{
  // For these vectors the cosine rounds to one ulp past -1, and an unclamped
  // acos returned NaN instead of 180 degrees.
  const Avogadro::Vector3 b(0.1, 1.0, -0.09);
  EXPECT_NEAR(bondAngle(b, b), 180.0, 1.0e-6);
  EXPECT_NEAR(bondAngle(b, -b), 0.0, 1.0e-6);

  // the same bonds through calculateAngle(): a-b-c in a straight line
  const Avogadro::Vector3 origin(0.0, 0.0, 0.0);
  EXPECT_NEAR(calculateAngle(origin - b, origin, origin + b), 180.0, 1.0e-6);
}

TEST(AngleToolsTest, bondAngleOfZeroLengthBondIsZero)
{
  const Avogadro::Vector3 zero(0.0, 0.0, 0.0);
  const Avogadro::Vector3 b(1.0, 0.0, 0.0);
  EXPECT_EQ(bondAngle(zero, b), 0.0);
  EXPECT_EQ(bondAngle(b, zero), 0.0);
  EXPECT_EQ(bondAngle(zero, zero), 0.0);
}
