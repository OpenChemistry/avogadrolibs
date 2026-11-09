/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "geometrytiming.h"

#include <atomic>

namespace Avogadro::Rendering {

namespace {
std::atomic<std::uint64_t> s_tessellateNanoseconds{ 0 };
}

void GeometryTiming::addTessellateNanoseconds(std::uint64_t nanoseconds)
{
  s_tessellateNanoseconds.fetch_add(nanoseconds, std::memory_order_relaxed);
}

std::uint64_t GeometryTiming::totalTessellateNanoseconds()
{
  return s_tessellateNanoseconds.load(std::memory_order_relaxed);
}

} // namespace Avogadro::Rendering
