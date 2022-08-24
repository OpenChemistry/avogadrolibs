/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "solidpipeline.h"

#include "solid_vs.h"

#include "solid_first_fs.h"

#include <iostream>

namespace Avogadro::Rendering {

SolidPipeline::SolidPipeline()
: m_pixelRatio(1.0f), m_aoEnabled(true), m_aoStrength(1.0f), m_edEnabled(true)
{
}

void initializeFramebuffer(GLuint *outFBO, GLuint *texRGB, GLuint *texDepth)
{
  glGenFramebuffers(1, outFBO);
  glBindFramebuffer(GL_FRAMEBUFFER, *outFBO);

  glGenTextures(1, texRGB);
  glBindTexture(GL_TEXTURE_2D, *texRGB);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, *texRGB, 0);

  glGenTextures(1, texDepth);
  glBindTexture(GL_TEXTURE_2D, *texDepth);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, GL_TEXTURE_2D, *texDepth, 0);
}

void SolidPipeline::initialize()
{
  initializeFramebuffer(&m_renderFBO, &m_renderTexture, &m_depthTexture);

  glGenBuffers(1, &m_screenVBO);
  glBindBuffer(GL_ARRAY_BUFFER, m_screenVBO);
  glBufferData(GL_ARRAY_BUFFER, sizeof(m_fullscreenQuad), m_fullscreenQuad, GL_STATIC_DRAW);

  m_screenVertexShader.setType(Shader::Vertex);
  m_screenVertexShader.setSource(solid_vs);
  if (!m_screenVertexShader.compile())
    std::cout << m_screenVertexShader.error() << std::endl;

  m_firstFragmentShader.setType(Shader::Fragment);
  m_firstFragmentShader.setSource(solid_first_fs);
  if (!m_firstFragmentShader.compile())
    std::cout << m_firstFragmentShader.error() << std::endl;

  m_firstStageShaders.attachShader(m_screenVertexShader);
  m_firstStageShaders.attachShader(m_firstFragmentShader);
  if (!m_firstStageShaders.link())
    std::cout << m_firstStageShaders.error() << std::endl;
}

void SolidPipeline::begin()
{
  glGetIntegerv(GL_FRAMEBUFFER_BINDING, (GLint *) &m_defaultFBO);
  glBindFramebuffer(GL_FRAMEBUFFER, m_renderFBO);
  GLenum drawBuffersList[1] = {GL_COLOR_ATTACHMENT0};
  glDrawBuffers(1, drawBuffersList);

  GLfloat tmp[5];
  glGetFloatv(GL_COLOR_CLEAR_VALUE, tmp);
  glGetFloatv(GL_DEPTH_CLEAR_VALUE, tmp + 4);
  glClearColor(0.0, 0.0, 0.0, 0.0);
  glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
  glClearColor(tmp[0], tmp[1], tmp[2], tmp[3]);
  glClearDepth(tmp[4]);
}

void attachStage(
  ShaderProgram &prog, const GLchar *nameRGB, GLuint texRGB, const GLchar *nameDepth, GLuint texDepth
) {
  prog.bind();
  GLuint programID;
  glGetIntegerv(GL_CURRENT_PROGRAM, (GLint *) &programID);

  GLuint attrRGB = glGetUniformLocation(programID, nameRGB);
  glActiveTexture(GL_TEXTURE0 + 1);
  glBindTexture(GL_TEXTURE_2D, texRGB);
  glUniform1i(attrRGB, 1);

  GLuint attrDepth = glGetUniformLocation(programID, nameDepth);
  glActiveTexture(GL_TEXTURE0 + 2);
  glBindTexture(GL_TEXTURE_2D, texDepth);
  glUniform1i(attrDepth, 2);
}

void SolidPipeline::end()
{
  // Render color component to a texture
  if (glIsFramebuffer(m_defaultFBO)) {
    glBindFramebuffer(GL_FRAMEBUFFER, m_defaultFBO);
    GLenum drawBuffersList[1] = {GL_COLOR_ATTACHMENT0};
    glDrawBuffers(1, drawBuffersList);
  } else {
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glDrawBuffer(GL_BACK);
  }

  // Draw fullscreen quad
  glEnableVertexAttribArray(0);
  glBindBuffer(GL_ARRAY_BUFFER, m_screenVBO);
  glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 0, nullptr);

  attachStage(m_firstStageShaders,
    "inRGBTex", m_renderTexture,
    "inDepthTex", m_depthTexture
  );
  m_firstStageShaders.setUniformValue("inAoEnabled", m_aoEnabled? 1.0f : 0.0f);
  m_firstStageShaders.setUniformValue("inAoStrength", m_aoStrength);
  m_firstStageShaders.setUniformValue("inEdEnabled", m_edEnabled? 1.0f : 0.0f);
  glDrawArrays(GL_TRIANGLES, 0, 6);

  glDisableVertexAttribArray(0);
}

void SolidPipeline::resize(int width, int height)
{
  width *= m_pixelRatio;
  height *= m_pixelRatio;

  glBindTexture(GL_TEXTURE_2D, m_renderTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, width, height, 0, GL_RGB, GL_UNSIGNED_BYTE, 0);

  glBindTexture(GL_TEXTURE_2D, m_depthTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_DEPTH_COMPONENT, width, height, 0, GL_DEPTH_COMPONENT, GL_UNSIGNED_BYTE, 0);
}

void SolidPipeline::setPixelRatio(float ratio)
{
  m_pixelRatio = ratio;
}

} // End namespace Avogadro::Rendering
