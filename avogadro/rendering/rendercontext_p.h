/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_RENDERCONTEXT_P_H
#define AVOGADRO_RENDERING_RENDERCONTEXT_P_H

#include "avogadrorenderingexport.h"
#include "shaderlibrary_p.h"

#include <cstdint>
#include <memory>

namespace Avogadro::Rendering {

/**
 * @class RenderContext rendercontext_p.h
 * @brief The GL resources that belong to one GL context and are shared by all
 * the drawables rendered in it.
 *
 * A GLRenderer owns one RenderContext and makes it current for the duration
 * of render(), so drawables find their shader programs through
 * RenderContext::current() instead of keeping process-wide copies that
 * outlive the context. Code that draws outside GLRenderer::render() gets a
 * temporary context from FallbackRenderContext.
 *
 * Private to the rendering library: the header is not installed. The class is
 * exported only so that the unit tests can link against it.
 */
class AVOGADRORENDERING_EXPORT RenderContext
{
public:
  RenderContext() = default;

  /** Releases the resources if that has not been done yet. */
  ~RenderContext();

  RenderContext(const RenderContext&) = delete;
  RenderContext& operator=(const RenderContext&) = delete;

  /**
   * A number that is unique in the process for each initialize() call, or 0
   * when the context is not initialized (including a FallbackRenderContext's
   * temporary context). Drawables compare it to the id they built their GL
   * buffers in to notice that the GL context was replaced.
   */
  std::uint64_t id() const { return m_id; }

  ShaderLibrary& shaders() { return m_shaders; }

  /** Start a new context life: assigns a fresh id(). */
  void initialize();

  /**
   * Delete the GL resources and set id() back to 0. The GL context must be
   * current. Safe to call more than once.
   */
  void releaseResources();

  /** An id that has not been handed out before, never 0. */
  static std::uint64_t nextId();

  /**
   * The context being rendered in on this thread, or nullptr outside a
   * ScopedRenderContext.
   */
  static RenderContext* current();

private:
  friend class ScopedRenderContext;
  static void setCurrent(RenderContext* context);

  std::uint64_t m_id = 0;
  ShaderLibrary m_shaders;
};

/**
 * Makes a RenderContext current on this thread for the life of the object,
 * then restores the previous one, so scopes can nest.
 */
class ScopedRenderContext
{
public:
  explicit ScopedRenderContext(RenderContext* context)
    : m_previous(RenderContext::current())
  {
    RenderContext::setCurrent(context);
  }
  ~ScopedRenderContext() { RenderContext::setCurrent(m_previous); }

  ScopedRenderContext(const ScopedRenderContext&) = delete;
  ScopedRenderContext& operator=(const ScopedRenderContext&) = delete;

private:
  RenderContext* m_previous;
};

/**
 * Put at the top of a drawable's render() and update(). Costs one thread-local
 * read when a RenderContext is already current (the case inside
 * GLRenderer::render()). Otherwise, for example when a Drawable is rendered
 * directly or by a GLRenderVisitor outside the renderer, it makes a temporary
 * context with id() 0 current, and deletes its programs on destruction, when
 * the caller's GL context is still current. Programs are rebuilt on every such
 * call, so this is a convenience for tests and tools, not a fast path.
 */
class FallbackRenderContext
{
public:
  FallbackRenderContext()
  {
    if (RenderContext::current() == nullptr) {
      m_context = std::make_unique<RenderContext>();
      m_scope = std::make_unique<ScopedRenderContext>(m_context.get());
    }
  }
  ~FallbackRenderContext()
  {
    // Leave the scope before deleting programs so nothing can find a context
    // that is being released.
    m_scope.reset();
    if (m_context)
      m_context->releaseResources();
  }

  FallbackRenderContext(const FallbackRenderContext&) = delete;
  FallbackRenderContext& operator=(const FallbackRenderContext&) = delete;

private:
  std::unique_ptr<RenderContext> m_context;
  std::unique_ptr<ScopedRenderContext> m_scope;
};

} // namespace Avogadro::Rendering

#endif // AVOGADRO_RENDERING_RENDERCONTEXT_P_H
