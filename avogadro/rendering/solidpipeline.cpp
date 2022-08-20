/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "solidpipeline.h"

namespace Avogadro::Rendering {

SolidPipeline::SolidPipeline()
{
}

void SolidPipeline::initialize()
{
  glGenTextures(1, &m_renderTexture);
  glBindTexture(GL_TEXTURE_2D, m_renderTexture);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
  resize(1366, 768);
  glGenFramebuffers(1, &m_renderFBO);
  glBindFramebuffer(GL_FRAMEBUFFER, m_renderFBO);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, m_renderTexture, 0);
}

void SolidPipeline::begin()
{
  glGetIntegerv(GL_FRAMEBUFFER_BINDING, (GLint *) &m_defaultFBO);
  glBindFramebuffer(GL_FRAMEBUFFER, m_renderFBO);
  GLenum drawBuffersList[1] = {GL_COLOR_ATTACHMENT0};
  glDrawBuffers(1, drawBuffersList);
}

void SolidPipeline::end()
{
  if (glIsFramebuffer(m_defaultFBO)) {
    glBindFramebuffer(GL_FRAMEBUFFER, m_defaultFBO);
    GLenum drawBuffersList[1] = {GL_COLOR_ATTACHMENT0};
    glDrawBuffers(1, drawBuffersList);
  } else {
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glDrawBuffer(GL_BACK);
  }
}

void SolidPipeline::resize(int width, int height)
{
  glBindTexture(GL_TEXTURE_2D, m_renderTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, width, height, 0, GL_RGB, GL_UNSIGNED_BYTE, 0);
}

} // End namespace Avogadro::Rendering
