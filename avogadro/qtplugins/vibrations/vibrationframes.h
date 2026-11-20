/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_VIBRATIONFRAMES_H
#define AVOGADRO_QTPLUGINS_VIBRATIONFRAMES_H

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

#include <vector>

namespace Avogadro::QtPlugins {

/**
 * Build one cycle of a vibration animation.
 *
 * Frame k (k = 0 ... framesPerCycle - 1) is
 * rest + sin(2 pi k / framesPerCycle) * peakScale * lx. Frame 0 is the rest
 * geometry and the last frame is not repeated at the end, so the cycle loops
 * seamlessly.
 *
 * @param rest The undisplaced positions.
 * @param lx The per-atom displacement of the mode.
 * @param peakScale The factor applied to @p lx at the peak of the cycle.
 * @param framesPerCycle The number of frames in the cycle.
 * @return The frames, or an empty array if the sizes differ, the arrays are
 * empty or @p framesPerCycle is less than 1.
 */
Core::Array<Core::Array<Vector3>> vibrationFrames(
  const Core::Array<Vector3>& rest, const Core::Array<Vector3>& lx,
  double peakScale, int framesPerCycle);

/**
 * @param framesWithModes Zero-based indices of the frames that have modes,
 * in any order.
 * @param current The active frame.
 * @return The entry of @p framesWithModes nearest to @p current, ignoring
 * @p current itself; the later frame wins a tie. -1 if there is no other
 * frame.
 */
int nearestVibrationFrame(const std::vector<int>& framesWithModes, int current);

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_VIBRATIONFRAMES_H
