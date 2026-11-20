/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vibrationframes.h"

#include <cmath>
#include <cstdlib>

namespace Avogadro::QtPlugins {

Core::Array<Core::Array<Vector3>> vibrationFrames(
  const Core::Array<Vector3>& rest, const Core::Array<Vector3>& lx,
  double peakScale, int framesPerCycle)
{
  Core::Array<Core::Array<Vector3>> frames;
  if (framesPerCycle < 1 || rest.empty() || rest.size() != lx.size())
    return frames;

  constexpr double twoPi = 6.283185307179586476925286766559;
  frames.reserve(static_cast<size_t>(framesPerCycle));
  for (int k = 0; k < framesPerCycle; ++k) {
    const double phase = twoPi * k / static_cast<double>(framesPerCycle);
    // Frame 0 must be exactly the rest geometry.
    const double scale = k == 0 ? 0.0 : std::sin(phase) * peakScale;
    Core::Array<Vector3> positions;
    positions.reserve(rest.size());
    for (size_t i = 0; i < rest.size(); ++i)
      positions.push_back(rest[i] + lx[i] * scale);
    frames.push_back(positions);
  }
  return frames;
}

int nearestVibrationFrame(const std::vector<int>& framesWithModes, int current)
{
  int best = -1;
  int bestDistance = 0;
  for (int frame : framesWithModes) {
    if (frame < 0 || frame == current)
      continue;
    const int distance = std::abs(frame - current);
    if (best < 0 || distance < bestDistance ||
        (distance == bestDistance && frame > best)) {
      best = frame;
      bestDistance = distance;
    }
  }
  return best;
}

} // namespace Avogadro::QtPlugins
