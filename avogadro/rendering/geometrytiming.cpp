/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "geometrytiming.h"

#include <atomic>

namespace Avogadro::Rendering {

namespace {
std::atomic<std::uint64_t> s_nanoseconds[2] = {};

std::atomic<std::uint64_t>& slot(GeometryTiming::Counter counter)
{
  return s_nanoseconds[counter == GeometryTiming::Counter::Upload ? 1 : 0];
}
} // namespace

void GeometryTiming::addNanoseconds(Counter counter, std::uint64_t nanoseconds)
{
  slot(counter).fetch_add(nanoseconds, std::memory_order_relaxed);
}

std::uint64_t GeometryTiming::totalNanoseconds(Counter counter)
{
  return slot(counter).load(std::memory_order_relaxed);
}

} // namespace Avogadro::Rendering
