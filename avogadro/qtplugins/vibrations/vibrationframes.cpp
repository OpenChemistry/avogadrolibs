/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vibrationframes.h"

#include <avogadro/core/avogadrocore.h>

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

  frames.reserve(static_cast<size_t>(framesPerCycle));
  for (int k = 0; k < framesPerCycle; ++k) {
    const double phase = 2.0 * PI_D * k / static_cast<double>(framesPerCycle);
    const double scale = std::sin(phase) * peakScale;
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
