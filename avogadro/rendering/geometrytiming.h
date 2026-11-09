/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_GEOMETRYTIMING_H
#define AVOGADRO_RENDERING_GEOMETRYTIMING_H

#include "avogadrorenderingexport.h"

#include <chrono>
#include <cstdint>

namespace Avogadro::Rendering {

/**
 * @class GeometryTiming geometrytiming.h <avogadro/rendering/geometrytiming.h>
 * @brief Process-wide wall time spent generating vertex and index data and
 * uploading it to the GPU.
 *
 * Together these split the CPU cost of a frame into tessellation and GL
 * upload. Both are monotonic counters; take differences to measure a span.
 * Callers time one update() or upload call, not individual vertices, so the
 * overhead is two clock reads.
 */
class AVOGADRORENDERING_EXPORT GeometryTiming
{
public:
  /** The counters. */
  enum class Counter
  {
    Tessellate, ///< generating vertex and index data
    Upload      ///< glBufferData
  };

  /** Add @p nanoseconds to the total of @p counter (thread-safe). */
  static void addNanoseconds(Counter counter, std::uint64_t nanoseconds);

  /** @return the summed time of @p counter in nanoseconds. */
  static std::uint64_t totalNanoseconds(Counter counter);

  /** Adds the lifetime of this object to a counter's total. */
  class Scope
  {
  public:
    explicit Scope(Counter counter = Counter::Tessellate)
      : m_counter(counter), m_start(std::chrono::steady_clock::now())
    {
    }
    ~Scope()
    {
      addNanoseconds(m_counter,
                     static_cast<std::uint64_t>(
                       std::chrono::duration_cast<std::chrono::nanoseconds>(
                         std::chrono::steady_clock::now() - m_start)
                         .count()));
    }
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;

  private:
    Counter m_counter;
    std::chrono::steady_clock::time_point m_start;
  };
};

} // namespace Avogadro::Rendering

#endif // AVOGADRO_RENDERING_GEOMETRYTIMING_H
