/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "solidpipeline.h"

#include "avogadrogl.h"
#include "shader.h"
#include "camera.h"
#include "shaderprogram.h"

#include "solid_vs.h"

#include "solid_first_fs.h"

#include <iostream>

namespace Avogadro::Rendering {

class SolidPipeline::Private
{
public:
  Private() {}

  void attachStage(ShaderProgram& prog, const GLchar* nameRGB, GLuint texRGB,
                   const GLchar* nameDepth, GLuint texDepth, int w, int h)
  {
    prog.bind();
    GLuint programID;
    glGetIntegerv(GL_CURRENT_PROGRAM, (GLint*)&programID);

    GLuint attrRGB = glGetUniformLocation(programID, nameRGB);
    glActiveTexture(GL_TEXTURE0 + 1);
    glBindTexture(GL_TEXTURE_2D, texRGB);
    glUniform1i(attrRGB, 1);

    GLuint attrDepth = glGetUniformLocation(programID, nameDepth);
    glActiveTexture(GL_TEXTURE0 + 2);
    glBindTexture(GL_TEXTURE_2D, texDepth);
    glUniform1i(attrDepth, 2);

    prog.setUniformValue("width", float(w));
    prog.setUniformValue("height", float(h));
  }

  GLuint defaultFBO;
  GLuint renderFBO;
  GLuint renderTexture;
  GLuint depthTexture;
  GLuint screenVBO;
  ShaderProgram firstStageShaders;
  Shader screenVertexShader;
  Shader firstFragmentShader;
};

static const GLfloat s_fullscreenQuad[] = {
  -1.0f, -1.0f, 0.0f,
  1.0f, -1.0f, 0.0f,
  -1.0f,  1.0f, 0.0f,
  -1.0f,  1.0f, 0.0f,
  1.0f, -1.0f, 0.0f,
  1.0f,  1.0f, 0.0f,
};

void initializeFramebuffer(GLuint* outFBO, GLuint* texRGB, GLuint* texDepth)
{
  glGenFramebuffers(1, outFBO);
  glBindFramebuffer(GL_FRAMEBUFFER, *outFBO);

  glGenTextures(1, texRGB);
  glBindTexture(GL_TEXTURE_2D, *texRGB);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
                         *texRGB, 0);

  glGenTextures(1, texDepth);
  glBindTexture(GL_TEXTURE_2D, *texDepth);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, GL_TEXTURE_2D,
                         *texDepth, 0);
}

SolidPipeline::SolidPipeline()
  : m_pixelRatio(1.0f), m_aoEnabled(true), m_aoStrength(1.0f),
    m_edEnabled(true), m_edStrength(1.0f), m_width(0), m_height(0),
    d(new Private), m_backgroundColor(0,0,0,0)
{
}

SolidPipeline::~SolidPipeline()
{
  delete d;
}

void SolidPipeline::initialize()
{
  initializeFramebuffer(&d->renderFBO, &d->renderTexture, &d->depthTexture);

  glGenBuffers(1, &d->screenVBO);
  glBindBuffer(GL_ARRAY_BUFFER, d->screenVBO);
  glBufferData(GL_ARRAY_BUFFER, sizeof(s_fullscreenQuad), s_fullscreenQuad,
               GL_STATIC_DRAW);

  d->screenVertexShader.setType(Shader::Vertex);
  d->screenVertexShader.setSource(solid_vs);
  if (!d->screenVertexShader.compile())
    std::cout << d->screenVertexShader.error() << std::endl;

  d->firstFragmentShader.setType(Shader::Fragment);
  d->firstFragmentShader.setSource(solid_first_fs);
  if (!d->firstFragmentShader.compile())
    std::cout << d->firstFragmentShader.error() << std::endl;

  d->firstStageShaders.attachShader(d->screenVertexShader);
  d->firstStageShaders.attachShader(d->firstFragmentShader);
  if (!d->firstStageShaders.link())
    std::cout << d->firstStageShaders.error() << std::endl;
}

void SolidPipeline::begin()
{
  glGetIntegerv(GL_FRAMEBUFFER_BINDING, (GLint*)&d->defaultFBO);
  glBindFramebuffer(GL_FRAMEBUFFER, d->renderFBO);
  GLenum drawBuffersList[1] = { GL_COLOR_ATTACHMENT0 };
  glDrawBuffers(1, drawBuffersList);

  GLfloat tmp[5];
  glGetFloatv(GL_COLOR_CLEAR_VALUE, tmp);
  glGetFloatv(GL_DEPTH_CLEAR_VALUE, tmp + 4);
  glClearColor(0.0, 0.0, 0.0, 0.0);
  glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
  glClearColor(tmp[0], tmp[1], tmp[2], tmp[3]);
  glClearDepth(tmp[4]);
}

void SolidPipeline::end()
{
  // Draw fullscreen quad
  glEnableVertexAttribArray(0);
  glBindBuffer(GL_ARRAY_BUFFER, d->screenVBO);
  glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 0, nullptr);

  // Draw to screen
  if (glIsFramebuffer(d->defaultFBO)) {
    glBindFramebuffer(GL_FRAMEBUFFER, d->defaultFBO);
    GLenum drawBuffersList[1] = { GL_COLOR_ATTACHMENT0 };
    glDrawBuffers(1, drawBuffersList);
  } else {
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glDrawBuffer(GL_BACK);
  }
  d->attachStage(d->firstStageShaders, "inRGBTex", d->renderTexture, "inDepthTex",
                 d->depthTexture, m_width, m_height);
  d->firstStageShaders.setUniformValue("inAoEnabled", m_aoEnabled ? 1.0f : 0.0f);
  d->firstStageShaders.setUniformValue("inAoStrength", m_aoStrength);
  d->firstStageShaders.setUniformValue("inEdStrength", m_edStrength);
  d->firstStageShaders.setUniformValue("inFogEnabled", m_fogEnabled ? 1.0f : 0.0f);
  d->firstStageShaders.setUniformValue("fogR", (m_backgroundColor[0])/255.0f);
  d->firstStageShaders.setUniformValue("fogG", (m_backgroundColor[1])/255.0f);
  d->firstStageShaders.setUniformValue("fogB", (m_backgroundColor[2])/255.0f);
  glDrawArrays(GL_TRIANGLES, 0, 6);
  
  // TODO: setting modelView uniform. WIP
  Camera camera;
  camera.setModelView(modelView);
  modelView = camera.modelView();
  // std::cout << modelView.matrix();
  glDisableVertexAttribArray(0);
}

void SolidPipeline::resize(int width, int height)
{
  m_width = width * m_pixelRatio;
  m_height = height * m_pixelRatio;

  glBindTexture(GL_TEXTURE_2D, d->renderTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, m_width, m_height, 0, GL_RGBA,
               GL_UNSIGNED_BYTE, 0);

  glBindTexture(GL_TEXTURE_2D, d->depthTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_DEPTH_COMPONENT, m_width, m_height, 0,
               GL_DEPTH_COMPONENT, GL_UNSIGNED_BYTE, 0);
}

void SolidPipeline::setPixelRatio(float ratio)
{
  m_pixelRatio = ratio;
}

} // End namespace Avogadro::Rendering
