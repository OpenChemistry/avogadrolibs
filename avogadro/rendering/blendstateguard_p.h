/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_BLENDSTATEGUARD_P_H
#define AVOGADRO_RENDERING_BLENDSTATEGUARD_P_H

#include "avogadrogl.h"

namespace Avogadro::Rendering {

/**
 * @brief Restores the caller's GL blend state when it goes out of scope.
 *
 * Captures whether GL_BLEND is enabled and the four blend factors on
 * construction. A drawable can then set whatever blending it needs while it
 * draws without knowing what its caller (or the renderer's translucent pass)
 * had set.
 */
class BlendStateGuard
{
public:
  BlendStateGuard()
    : m_enabled(glIsEnabled(GL_BLEND) == GL_TRUE), m_srcRgb(GL_SRC_ALPHA),
      m_dstRgb(GL_ONE_MINUS_SRC_ALPHA), m_srcAlpha(GL_ONE), m_dstAlpha(GL_ONE)
  {
    glGetIntegerv(GL_BLEND_SRC_RGB, &m_srcRgb);
    glGetIntegerv(GL_BLEND_DST_RGB, &m_dstRgb);
    glGetIntegerv(GL_BLEND_SRC_ALPHA, &m_srcAlpha);
    glGetIntegerv(GL_BLEND_DST_ALPHA, &m_dstAlpha);
  }

  ~BlendStateGuard()
  {
    glBlendFuncSeparate(
      static_cast<GLenum>(m_srcRgb), static_cast<GLenum>(m_dstRgb),
      static_cast<GLenum>(m_srcAlpha), static_cast<GLenum>(m_dstAlpha));
    if (m_enabled)
      glEnable(GL_BLEND);
    else
      glDisable(GL_BLEND);
  }

  BlendStateGuard(const BlendStateGuard&) = delete;
  BlendStateGuard& operator=(const BlendStateGuard&) = delete;

private:
  bool m_enabled;
  GLint m_srcRgb;
  GLint m_dstRgb;
  GLint m_srcAlpha;
  GLint m_dstAlpha;
};

} // namespace Avogadro::Rendering

#endif // AVOGADRO_RENDERING_BLENDSTATEGUARD_P_H
