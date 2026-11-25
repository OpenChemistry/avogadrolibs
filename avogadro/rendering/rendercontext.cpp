/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "rendercontext_p.h"

#include <atomic>

namespace Avogadro::Rendering {

namespace {
std::atomic<std::uint64_t> s_nextId{ 1 };
thread_local RenderContext* s_current = nullptr;
} // namespace

RenderContext::~RenderContext()
{
  releaseResources();
}

std::uint64_t RenderContext::nextId()
{
  return s_nextId.fetch_add(1, std::memory_order_relaxed);
}

void RenderContext::initialize()
{
  // A GL buffer left from an earlier life belongs to a context that is gone
  // (or was cleaned up, which released it already): never delete it here.
  m_camera.abandon();
  m_id = nextId();
}

void RenderContext::releaseResources()
{
  m_shaders.releaseResources();
  m_camera.release();
  m_id = 0;
}

RenderContext* RenderContext::current()
{
  return s_current;
}

void RenderContext::setCurrent(RenderContext* context)
{
  s_current = context;
}

} // namespace Avogadro::Rendering
