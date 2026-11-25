/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_RENDERCONTEXT_P_H
#define AVOGADRO_RENDERING_RENDERCONTEXT_P_H

#include "avogadrorenderingexport.h"
#include "camerabuffer_p.h"
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

  /**
   * The uniform buffer that holds the camera for every program in this
   * context. Created on first use, so a GL context must be current when
   * cameraBuffer().use() is called.
   */
  CameraBuffer& cameraBuffer() { return m_camera; }

  /** Start a new context life: assigns a fresh id(). */
  void initialize();

  /**
   * Delete the GL resources and set id() back to 0. The GL context must be
   * current. Safe to call more than once.
   */
  void releaseResources();

  /**
   * The context being rendered in on this thread, or nullptr outside a
   * ScopedRenderContext.
   */
  static RenderContext* current();

  /**
   * The program for @p id in the current context, or nullptr if there is no
   * current context or the program failed to build. The pointer is valid only
   * while the context is (inside a FallbackRenderContext scope for a
   * drawable).
   */
  static ShaderProgram* currentProgram(ShaderId id)
  {
    RenderContext* context = current();
    return context ? context->shaders().program(id) : nullptr;
  }

  /**
   * Make the current context's camera buffer hold @p camera (it uploads only
   * if the camera differs from the one it holds) and bind it. Prints an error
   * and returns false if there is no context or the buffer could not be
   * created.
   */
  static bool useCamera(const Camera& camera);

private:
  friend class ScopedRenderContext;
  static void setCurrent(RenderContext* context);

  std::uint64_t m_id = 0;
  ShaderLibrary m_shaders;
  CameraBuffer m_camera;
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
 * Remembers which RenderContext a drawable's GL objects were created in, so
 * that the drawable can notice that the GL context was destroyed and replaced
 * (for example when Qt moves a GLWidget to another window).
 *
 * Only real contexts count: a context with id() 0 (a FallbackRenderContext, or
 * a RenderContext that was never initialized) neither triggers a change nor is
 * remembered.
 */
class ContextStamp
{
public:
  /**
   * Call with the drawable's rendering under way, before using its GL objects.
   * @return true if the objects were created in a context that has since been
   * replaced. They belong to the dead context, so the drawable has to forget
   * them (abandon(), never delete) and build new ones. Returns true only once
   * per replacement.
   */
  bool replaced() { return replaced(m_id); }

  /**
   * The same check for a drawable that keeps the id itself, because its GL
   * objects live in a public struct that cannot include this header (such as
   * Line). @p storedId is 0 until a real context has been seen.
   */
  static bool replaced(std::uint64_t& storedId)
  {
    const RenderContext* context = RenderContext::current();
    const std::uint64_t id = context ? context->id() : 0;
    if (id == 0)
      return false;
    const bool changed = storedId != 0 && storedId != id;
    storedId = id;
    return changed;
  }

  /**
   * If the GL context was replaced, the GL objects belong to the dead one:
   * forget them (abandon(), never delete) so that they are rebuilt.
   * @return true if they were abandoned, so the caller has to mark its data
   * dirty.
   */
  template <class... Objects>
  bool forgetIfReplaced(Objects&... objects)
  {
    return forgetIfReplaced(m_id, objects...);
  }

  /** The same for a drawable that keeps the id itself (see replaced()). */
  template <class... Objects>
  static bool forgetIfReplaced(std::uint64_t& storedId, Objects&... objects)
  {
    if (!replaced(storedId))
      return false;
    (objects.abandon(), ...);
    return true;
  }

private:
  std::uint64_t m_id = 0;
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
