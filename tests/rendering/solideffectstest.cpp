/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// These tests make no GL calls: there is no GL context here.

#include <gtest/gtest.h>

#include <solideffects_p.h>

#include <cmath>
#include <limits>

using namespace Avogadro::Rendering;

namespace {
constexpr float Inf = std::numeric_limits<float>::infinity();
constexpr float NaN = std::numeric_limits<float>::quiet_NaN();
} // namespace

TEST(SolidEffectsTest, fogStrengthMapping)
{
  EXPECT_FLOAT_EQ(fogSettings(1.0f, 1.0f).amount, 0.4f);
  EXPECT_NEAR(fogSettings(5.0f, 1.0f).amount, 5.0f / 6.5f, 1e-6);
  float previous = 0.0f;
  for (float s = 0.1f; s <= 20.0f; s += 0.1f) {
    const float amount = fogSettings(s, 1.0f).amount;
    EXPECT_GT(amount, previous);
    EXPECT_LT(amount, 1.0f);
    previous = amount;
  }
  // Zero, negative and non-finite strengths are off.
  for (float s : { 0.0f, -0.1f, -20.0f, NaN, -Inf })
    EXPECT_EQ(fogSettings(s, 1.0f).amount, 0.0f);
  EXPECT_LT(fogSettings(Inf, 1.0f).amount, 1.0f + 1e-6f);
}

TEST(SolidEffectsTest, fogPositionMapping)
{
  EXPECT_FLOAT_EQ(fogSettings(1.0f, 1.0f).startRadii, 0.0f);
  EXPECT_FLOAT_EQ(fogSettings(1.0f, -20.0f).startRadii, -2.1f);
  EXPECT_FLOAT_EQ(fogSettings(1.0f, 20.0f).startRadii, 1.9f);
  // Clamped to the dialog's range; garbage means the default.
  EXPECT_FLOAT_EQ(fogSettings(1.0f, -500.0f).startRadii, -2.1f);
  EXPECT_FLOAT_EQ(fogSettings(1.0f, 500.0f).startRadii, 1.9f);
  EXPECT_FLOAT_EQ(fogSettings(1.0f, NaN).startRadii, 0.0f);
}

TEST(SolidEffectsTest, fogFactorIsALinearRamp)
{
  const FogSettings fog = fogSettings(1.0f, 1.0f); // 0.4, starts at center
  const float center = 50.0f, radius = 10.0f;
  EXPECT_FLOAT_EQ(fogFactor(fog, 30.0f, center, radius), 0.0f);
  EXPECT_FLOAT_EQ(fogFactor(fog, 50.0f, center, radius), 0.0f);
  EXPECT_NEAR(fogFactor(fog, 55.0f, center, radius), 0.2f, 1e-6);
  EXPECT_NEAR(fogFactor(fog, 60.0f, center, radius), 0.4f, 1e-6);
  EXPECT_NEAR(fogFactor(fog, 500.0f, center, radius), 0.4f, 1e-6);
  // Monotonic and bounded for every position.
  for (float position = -20.0f; position <= 20.0f; position += 1.0f) {
    const FogSettings f = fogSettings(3.0f, position);
    float previous = 0.0f;
    for (float z = 0.0f; z < 100.0f; z += 0.5f) {
      const float value = fogFactor(f, z, center, radius);
      EXPECT_GE(value, previous);
      EXPECT_LE(value, f.amount + 1e-6f);
      EXPECT_TRUE(std::isfinite(value));
      previous = value;
    }
  }
}

TEST(SolidEffectsTest, fogFactorGuardsDegenerateInput)
{
  const FogSettings fog = fogSettings(5.0f, 20.0f); // start near the back
  EXPECT_EQ(fogFactor(fog, 10.0f, 10.0f, 0.0f), 0.0f);
  EXPECT_EQ(fogFactor(fog, 10.0f, 10.0f, -1.0f), 0.0f);
  EXPECT_EQ(fogFactor(fog, NaN, 10.0f, 1.0f), 0.0f);
  EXPECT_EQ(fogFactor(fog, 10.0f, Inf, 1.0f), 0.0f);
  EXPECT_EQ(fogFactor(FogSettings(), 10.0f, 10.0f, 1.0f), 0.0f);
  // A start beyond the back of the span still gives a finite value.
  for (float z = 0.0f; z < 30.0f; z += 0.25f) {
    const float v = fogFactor(fog, z, 10.0f, 1.0f);
    EXPECT_TRUE(std::isfinite(v));
    EXPECT_GE(v, 0.0f);
    EXPECT_LE(v, fog.amount + 1e-6f);
  }
}

TEST(SolidEffectsTest, depthOfFieldMapping)
{
  EXPECT_FLOAT_EQ(depthOfFieldSettings(1.0f, 1.0f).blurPerRadius, 8.0f);
  EXPECT_FLOAT_EQ(depthOfFieldSettings(2.0f, 1.0f).blurPerRadius, 16.0f);
  EXPECT_FLOAT_EQ(depthOfFieldSettings(1000.0f, 1.0f).blurPerRadius, 80.0f);
  for (float s : { 0.0f, -1.0f, NaN, -Inf })
    EXPECT_EQ(depthOfFieldSettings(s, 1.0f).blurPerRadius, 0.0f);
  // Position: front, center and back of the bounding sphere.
  EXPECT_FLOAT_EQ(depthOfFieldSettings(1.0f, 0.0f).focusRadii, -1.0f);
  EXPECT_FLOAT_EQ(depthOfFieldSettings(1.0f, 0.5f).focusRadii, -0.5f);
  EXPECT_FLOAT_EQ(depthOfFieldSettings(1.0f, 1.0f).focusRadii, 0.0f);
  EXPECT_FLOAT_EQ(depthOfFieldSettings(1.0f, 20.0f).focusRadii, 1.0f);
  EXPECT_FLOAT_EQ(depthOfFieldSettings(1.0f, -5.0f).focusRadii, -1.0f);
  EXPECT_FLOAT_EQ(depthOfFieldSettings(1.0f, 99.0f).focusRadii, 1.0f);
  EXPECT_FLOAT_EQ(depthOfFieldSettings(1.0f, NaN).focusRadii, 0.0f);
}

TEST(SolidEffectsTest, circleOfConfusion)
{
  const DepthOfFieldSettings dof = depthOfFieldSettings(1.0f, 1.0f);
  const float center = 50.0f, radius = 10.0f;
  EXPECT_FLOAT_EQ(circleOfConfusion(dof, 50.0f, center, radius), 0.0f);
  EXPECT_FLOAT_EQ(circleOfConfusion(dof, 60.0f, center, radius), 8.0f);
  EXPECT_FLOAT_EQ(circleOfConfusion(dof, 40.0f, center, radius), 8.0f);
  EXPECT_FLOAT_EQ(circleOfConfusion(dof, 1000.0f, center, radius),
                  MaxDepthOfFieldBlur);
  // Linear in the distance from the focus until it is clamped.
  EXPECT_NEAR(circleOfConfusion(dof, 52.5f, center, radius), 2.0f, 1e-5);
  // Off or degenerate: no blur, never NaN.
  EXPECT_EQ(circleOfConfusion(DepthOfFieldSettings(), 60.0f, center, radius),
            0.0f);
  EXPECT_EQ(circleOfConfusion(dof, 60.0f, center, 0.0f), 0.0f);
  EXPECT_EQ(circleOfConfusion(dof, NaN, center, radius), 0.0f);
}

TEST(SolidEffectsTest, occlusionBufferIsHalfTheFrameRoundedUp)
{
  EXPECT_EQ(occlusionBufferSize(1920), 960);
  EXPECT_EQ(occlusionBufferSize(1080), 540);
  // An odd frame's last row or column still gets a texel.
  EXPECT_EQ(occlusionBufferSize(63), 32);
  EXPECT_EQ(occlusionBufferSize(47), 24);
  EXPECT_EQ(occlusionBufferSize(3), 2);
  EXPECT_EQ(occlusionBufferSize(2), 1);
  // Never empty, whatever the frame.
  EXPECT_EQ(occlusionBufferSize(1), 1);
  EXPECT_EQ(occlusionBufferSize(0), 1);
  EXPECT_EQ(occlusionBufferSize(-5), 1);
  // And the texels always cover the frame: 2 per texel, at most one over.
  for (int size = 1; size < 4096; ++size) {
    const int texels = occlusionBufferSize(size);
    EXPECT_GE(2 * texels, size);
    EXPECT_LE(2 * texels - size, 1);
  }
  EXPECT_GT(occlusionBufferSize(std::numeric_limits<int>::max()), 0);
}
