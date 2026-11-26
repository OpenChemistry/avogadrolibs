/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "rendercontext_p.h"

#include <atomic>
#include <iostream>

namespace Avogadro::Rendering {

namespace {
std::atomic<std::uint64_t> s_nextId{ 1 };

// An id that has not been handed out before, never 0.
std::uint64_t nextId()
{
  return s_nextId.fetch_add(1, std::memory_order_relaxed);
}

thread_local RenderContext* s_current = nullptr;
} // namespace

RenderContext::~RenderContext()
{
  releaseResources();
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

bool RenderContext::useCamera(const Camera& camera)
{
  if (s_current != nullptr && s_current->cameraBuffer().use(camera))
    return true;
  std::cout << "Could not update the camera buffer." << '\n';
  return false;
}

void RenderContext::setCurrent(RenderContext* context)
{
  s_current = context;
}

} // namespace Avogadro::Rendering
