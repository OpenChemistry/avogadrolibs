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
 * @brief Process-wide wall time spent generating vertex and index data.
 *
 * Together with BufferObject::totalUploadNanoseconds() this splits the CPU
 * cost of a frame into tessellation and GL upload. Both are monotonic
 * counters; take differences to measure a span. Geometry classes time one
 * update() call, not individual vertices, so the overhead is two clock reads.
 */
class AVOGADRORENDERING_EXPORT GeometryTiming
{
public:
  /** Add @p nanoseconds to the tessellation total (thread-safe). */
  static void addTessellateNanoseconds(std::uint64_t nanoseconds);

  /** @return the summed tessellation time in nanoseconds. */
  static std::uint64_t totalTessellateNanoseconds();

  /** Adds the lifetime of this object to the tessellation total. */
  class Scope
  {
  public:
    Scope() : m_start(std::chrono::steady_clock::now()) {}
    ~Scope()
    {
      addTessellateNanoseconds(static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now() - m_start)
          .count()));
    }
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;

  private:
    std::chrono::steady_clock::time_point m_start;
  };
};

} // namespace Avogadro::Rendering

#endif // AVOGADRO_RENDERING_GEOMETRYTIMING_H
