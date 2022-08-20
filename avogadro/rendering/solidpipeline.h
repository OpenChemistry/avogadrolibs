/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_SOLIDPIPELINE_H
#define AVOGADRO_RENDERING_SOLIDPIPELINE_H

#include "avogadrogl.h"

namespace Avogadro {
namespace Rendering {

class SolidPipeline
{
public:
  SolidPipeline();

  /**
   * @brief Initialize OpenGL objects.
   */
  void initialize();

  /**
   * @brief Begin solid geometry rendering.
   */
  void begin();
  
  /**
   * @brief End solid geometry rendering and apply screen-space shaders.
   */
  void end();
  
  /**
   * @brief Resize buffers for width x height viewport.
   */
  void resize(int width, int height);

private:
  GLuint m_defaultFBO;
  GLuint m_renderTexture;
  GLuint m_renderFBO;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif
