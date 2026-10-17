/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_RENDERTIMINGS_H
#define AVOGADRO_RENDERING_RENDERTIMINGS_H

#include "avogadrorenderingexport.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Avogadro {
namespace Rendering {

/**
 * @struct PassTiming rendertimings.h <avogadro/rendering/rendertimings.h>
 * @brief CPU and GPU time spent in one section of GLRenderer::render().
 */
struct AVOGADRORENDERING_EXPORT PassTiming
{
  /** The section name, e.g. "solid" or "translucent". */
  std::string name;
  /** Wall-clock time spent issuing the section's GL commands, in ms. */
  double cpuMs = 0.0;
  /** GPU time for the section in ms; negative when unavailable. */
  double gpuMs = -1.0;
};

/**
 * @struct RenderTimings rendertimings.h <avogadro/rendering/rendertimings.h>
 * @brief Timings for one rendered frame. See GLRenderer::setTimingEnabled().
 */
struct AVOGADRORENDERING_EXPORT RenderTimings
{
  /** Counter of timed render() calls, starting at 1 (0 means no data yet). */
  std::uint64_t frame = 0;
  std::vector<PassTiming> passes;
  /** Bytes handed to glBufferData while the frame was rendered. */
  std::uint64_t bufferBytesUploaded = 0;
  /** True if the passes carry GPU times. */
  bool gpuTimingAvailable = false;

  double totalCpuMs() const
  {
    double total = 0.0;
    for (const PassTiming& pass : passes)
      total += pass.cpuMs;
    return total;
  }

  /** @return the summed GPU time in ms, or -1 if it is unavailable. */
  double totalGpuMs() const
  {
    if (!gpuTimingAvailable)
      return -1.0;
    double total = 0.0;
    for (const PassTiming& pass : passes)
      total += pass.gpuMs;
    return total;
  }
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_RENDERTIMINGS_H
