/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "solideffects_p.h"

#include <algorithm>
#include <cmath>

namespace Avogadro::Rendering {

namespace {

// The strength at which the fog mixes in half of the background.
constexpr float FogHalfStrength = 1.5f;
// The ramp is never shorter than this fraction of the scene radius, so that
// pushing the start past the back of the scene cannot divide by zero.
constexpr float MinimumFogRampRadii = 0.05f;
// Logical pixels of blur, per scene radius from the focus, for strength 1.
constexpr float BlurPerStrength = 8.0f;
constexpr float MaxDepthOfFieldStrength = 10.0f;

float clampedFinite(float value, float low, float high, float fallback)
{
  if (!std::isfinite(value))
    return fallback;
  return std::clamp(value, low, high);
}

} // namespace

FogSettings fogSettings(float strength, float position)
{
  FogSettings settings;
  if (!std::isfinite(strength) || strength <= 0.0f)
    return settings;
  settings.amount = strength / (strength + FogHalfStrength);
  settings.startRadii =
    std::min(0.1f * (clampedFinite(position, -20.0f, 20.0f, 1.0f) - 1.0f),
             1.0f - MinimumFogRampRadii);
  return settings;
}

float fogFactor(const FogSettings& settings, float depth, float centerDepth,
                float radius)
{
  if (!(settings.amount > 0.0f) || !(radius > 0.0f) || !std::isfinite(depth) ||
      !std::isfinite(centerDepth)) {
    return 0.0f;
  }
  const float start = centerDepth + settings.startRadii * radius;
  const float end = centerDepth + radius;
  const float length = std::max(end - start, MinimumFogRampRadii * radius);
  return settings.amount * std::clamp((depth - start) / length, 0.0f, 1.0f);
}

DepthOfFieldSettings depthOfFieldSettings(float strength, float position)
{
  DepthOfFieldSettings settings;
  settings.blurPerRadius = 0.0f;
  if (!std::isfinite(strength) || strength <= 0.0f)
    return settings;
  settings.blurPerRadius =
    BlurPerStrength * std::min(strength, MaxDepthOfFieldStrength);
  const float p = clampedFinite(position, 0.0f, 20.0f, 1.0f);
  settings.focusRadii = p < 1.0f ? p - 1.0f : (p - 1.0f) / 19.0f;
  return settings;
}

float circleOfConfusion(const DepthOfFieldSettings& settings, float depth,
                        float centerDepth, float radius)
{
  if (!(settings.blurPerRadius > 0.0f) || !(radius > 0.0f) ||
      !std::isfinite(depth) || !std::isfinite(centerDepth)) {
    return 0.0f;
  }
  const float focus = centerDepth + settings.focusRadii * radius;
  const float blur = settings.blurPerRadius * std::abs(depth - focus) / radius;
  return std::min(blur, settings.maxBlur);
}

int occlusionBufferSize(int size)
{
  // Written as a division and a remainder so that size + 1 cannot overflow.
  if (size <= 1)
    return 1;
  return size / 2 + size % 2;
}

} // namespace Avogadro::Rendering
