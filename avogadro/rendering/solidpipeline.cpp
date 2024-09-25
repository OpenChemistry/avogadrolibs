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
#include "solid_fog_fs.h"

#include <iostream>

#include <cmath>

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
  ShaderProgram fogStageShaders;
  Shader screenVertexShader;
  Shader firstFragmentShader;
  Shader fogFragmentShader;         
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
  : m_pixelRatio(1.0f), m_aoEnabled(true), m_dofEnabled(true), m_aoStrength(1.0f),
    m_fogStrength(1.0f), m_fogPosition(1.0), m_fogEnabled(true), m_edEnabled(true),
    m_edStrength(1.0f), m_width(0), m_height(0), m_dofStrength(1.0f),
    m_dofPosition(1.0), m_backgroundColor(0,0,0,0), d(new Private)
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

  // shader program for fog.
  d->fogFragmentShader.setType(Shader::Fragment);
  d->fogFragmentShader.setSource(solid_fog_fs);
  if(!d->fogFragmentShader.compile())
    std::cout << d->fogFragmentShader.error() << std::endl;

  // shader for ao and blur.         
  d->firstFragmentShader.setType(Shader::Fragment);
  d->firstFragmentShader.setSource(solid_first_fs);
  if (!d->firstFragmentShader.compile())
    std::cout << d->firstFragmentShader.error() << std::endl;

  
  d->firstStageShaders.attachShader(d->screenVertexShader);
  d->firstStageShaders.attachShader(d->firstFragmentShader);
  if (!d->firstStageShaders.link())
    std::cout << d->firstStageShaders.error() << std::endl;

  // shaderProgram for fog.     
  d->fogStageShaders.attachShader(d->screenVertexShader);
  d->fogStageShaders.attachShader(d->fogFragmentShader);
  if (!d->fogStageShaders.link())
    std::cout << d->fogStageShaders.error() << std::endl;

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

  if(m_fogEnabled){
  // shader for fog.
  d->attachStage(d->fogStageShaders, "inRGBTex", d->renderTexture, "inDepthTex",
                 d->depthTexture, m_width, m_height);
  d->fogStageShaders.setUniformValue("inFogStrength", m_fogStrength);
  d->fogStageShaders.setUniformValue("inFogPosition", m_fogPosition);
  d->fogStageShaders.setUniformValue("fogR", (m_backgroundColor[0])/255.0f);
  d->fogStageShaders.setUniformValue("fogG", (m_backgroundColor[1])/255.0f);
  d->fogStageShaders.setUniformValue("fogB", (m_backgroundColor[2])/255.0f);
  } else {
  d->attachStage(d->firstStageShaders, "inRGBTex", d->renderTexture, "inDepthTex",
                 d->depthTexture, m_width, m_height);
  d->firstStageShaders.setUniformValue("inAoEnabled", m_aoEnabled ? 1.0f : 0.0f);
  d->firstStageShaders.setUniformValue("inDofEnabled", m_dofEnabled ? m_dofStrength : 0.0f);
  d->firstStageShaders.setUniformValue("inDofStrength", ((m_dofStrength) * 100.0f));
  d->firstStageShaders.setUniformValue("inDofPosition", ((m_dofPosition) /10.0f));
  d->firstStageShaders.setUniformValue("inAoStrength", m_aoStrength);
  d->firstStageShaders.setUniformValue("inEdStrength", m_edStrength);
  }

  glDrawArrays(GL_TRIANGLES, 0, 6);
  glDisableVertexAttribArray(0);
}

void SolidPipeline::adjustOffset(const Camera& cam) {

    // The numbers used in calculations are random.
    // They help define an offset with the projection-matrix
    // to make the fog dynamic as the molecule moves away 
    // from the camera or come closer.
    Eigen::Matrix4f projectView = cam.projection().matrix();

    float project = ((((5000 + projectView(2,3) * 1000)/6) + 55) * 100);

    float offSet = 0.000102337 * pow(project,2) - 3.84689 * project + 36182.2;
    if(project >= 21018.106 && project<21595.588){
      offSet = 2.63129 * project - 54768.4;
    }
    else if(project >= 21595.588 ){
     offSet = 9.952 * project - 212865;
    }
    // setting uniforms.
    if (m_fogEnabled){
    d->fogStageShaders.setUniformValue("uoffset", offSet);
    } else {
    d->firstStageShaders.setUniformValue("uoffset", offSet);
    }

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