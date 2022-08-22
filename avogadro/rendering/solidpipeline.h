/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_SOLIDPIPELINE_H
#define AVOGADRO_RENDERING_SOLIDPIPELINE_H

#include "avogadrogl.h"
#include "shader.h"
#include "shaderprogram.h"

static const GLfloat m_fullscreenQuad[] = {
  -1.0f, -1.0f, 0.0f,
  1.0f, -1.0f, 0.0f,
  -1.0f,  1.0f, 0.0f,
  -1.0f,  1.0f, 0.0f,
  1.0f, -1.0f, 0.0f,
  1.0f,  1.0f, 0.0f,
};

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

  /**
   * @brief Set pixel ratio (1.0 on standard displays, 2.0 on Retina, etc.).
   */
  void setPixelRatio(float ratio);

private:
  GLuint m_defaultFBO;
  GLuint m_renderFBO;
  GLuint m_renderTexture;
  GLuint m_depthTexture;
  GLuint m_screenVBO;
  ShaderProgram m_firstStageShaders;
  Shader m_screenVertexShader;
  Shader m_firstFragmentShader;
  GLuint m_firstTexAttributeID;
  float m_pixelRatio;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif
