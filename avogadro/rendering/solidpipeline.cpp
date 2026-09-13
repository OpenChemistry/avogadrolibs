/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "solidpipeline.h"

#include "avogadrogl.h"
#include "camera.h"
#include "shader.h"
#include "shaderprogram.h"

#include "solid_vs.h"

#include "solid_first_fs.h"

#include "solid_ao_fs.h"

#include <iostream>

#include <cmath>

namespace Avogadro::Rendering {

// Texture units shared by the pipeline's stages. Kept together so that adding
// a sampler cannot silently collide with one already in use.
namespace {
constexpr int TextureUnitRGB = 1;
constexpr int TextureUnitDepth = 2;
constexpr int TextureUnitAo = 3;
} // namespace

class SolidPipeline::Private
{
public:
  Private() {}

  // Point a sampler uniform in the currently bound program at a texture.
  void bindSampler(const GLchar* name, GLuint texture, int unit)
  {
    GLuint programID;
    glGetIntegerv(GL_CURRENT_PROGRAM, (GLint*)&programID);
    GLuint location = glGetUniformLocation(programID, name);
    glActiveTexture(GL_TEXTURE0 + unit);
    glBindTexture(GL_TEXTURE_2D, texture);
    glUniform1i(location, unit);
  }

  void attachStage(ShaderProgram& prog, const GLchar* nameRGB, GLuint texRGB,
                   const GLchar* nameDepth, GLuint texDepth, int w, int h)
  {
    prog.bind();
    bindSampler(nameRGB, texRGB, TextureUnitRGB);
    bindSampler(nameDepth, texDepth, TextureUnitDepth);
    prog.setUniformValue("width", float(w));
    prog.setUniformValue("height", float(h));
  }

  GLuint defaultFBO;
  GLint defaultViewport[4] = { 0, 0, 0, 0 };
  GLuint renderFBO;
  GLuint renderTexture;
  GLuint depthTexture;
  GLuint aoFBO;
  GLuint aoTexture;
  GLuint screenVAO;
  GLuint screenVBO;
  ShaderProgram firstStageShaders;
  ShaderProgram aoStageShaders;
  Shader screenVertexShader;
  Shader firstFragmentShader;
  Shader aoFragmentShader;
};

static const GLfloat s_fullscreenQuad[] = {
  -1.0f, -1.0f, 0.0f, 1.0f, -1.0f, 0.0f, -1.0f, 1.0f, 0.0f,
  -1.0f, 1.0f,  0.0f, 1.0f, -1.0f, 0.0f, 1.0f,  1.0f, 0.0f,
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

// The ambient occlusion term is rendered on its own so the compositing stage
// can filter it. It needs a float format: the term brightens as well as
// darkens, and goes above 1.0.
void initializeAoFramebuffer(GLuint* outFBO, GLuint* texAo)
{
  glGenFramebuffers(1, outFBO);
  glBindFramebuffer(GL_FRAMEBUFFER, *outFBO);

  glGenTextures(1, texAo);
  glBindTexture(GL_TEXTURE_2D, *texAo);
  // The blur reads exact texel centres, so no filtering is wanted here.
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
                         *texAo, 0);
}

SolidPipeline::SolidPipeline()
  : m_pixelRatio(1.0f), m_aoEnabled(false), m_dofStrength(1.0f),
    m_dofPosition(1.0), m_dofEnabled(false), m_fogPosition(1.0),
    m_backgroundColor(0, 0, 0, 0), m_fogEnabled(true), m_aoStrength(1.0f),
    m_fogStrength(1.0f), m_edEnabled(false), m_edStrength(1.0f), m_width(0),
    m_height(0), d(new Private)
{
}

SolidPipeline::~SolidPipeline()
{
  delete d;
}

void SolidPipeline::initialize()
{
  initializeFramebuffer(&d->renderFBO, &d->renderTexture, &d->depthTexture);
  initializeAoFramebuffer(&d->aoFBO, &d->aoTexture);
  // Each helper leaves its own framebuffer bound; settle on the one the
  // pipeline renders into.
  glBindFramebuffer(GL_FRAMEBUFFER, d->renderFBO);

  // Create VAO for fullscreen quad (required for OpenGL Core Profile)
  glGenVertexArrays(1, &d->screenVAO);
  glBindVertexArray(d->screenVAO);

  glGenBuffers(1, &d->screenVBO);
  glBindBuffer(GL_ARRAY_BUFFER, d->screenVBO);
  glBufferData(GL_ARRAY_BUFFER, sizeof(s_fullscreenQuad), s_fullscreenQuad,
               GL_STATIC_DRAW);

  // Set up vertex attribute for the fullscreen quad
  glEnableVertexAttribArray(0);
  glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 0, nullptr);

  glBindVertexArray(0);

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

  d->aoFragmentShader.setType(Shader::Fragment);
  d->aoFragmentShader.setSource(solid_ao_fs);
  if (!d->aoFragmentShader.compile())
    std::cout << d->aoFragmentShader.error() << std::endl;

  d->aoStageShaders.attachShader(d->screenVertexShader);
  d->aoStageShaders.attachShader(d->aoFragmentShader);
  if (!d->aoStageShaders.link())
    std::cout << d->aoStageShaders.error() << std::endl;

  // here is the end of the code that needs to be compared
}

void SolidPipeline::begin()
{
  glGetIntegerv(GL_FRAMEBUFFER_BINDING, (GLint*)&d->defaultFBO);
  glGetIntegerv(GL_VIEWPORT, d->defaultViewport);
  glBindFramebuffer(GL_FRAMEBUFFER, d->renderFBO);
  GLenum drawBuffersList[1] = { GL_COLOR_ATTACHMENT0 };
  glDrawBuffers(1, drawBuffersList);

  // The offscreen buffers are sized independently of the default framebuffer,
  // so the viewport must be set to match them rather than inherited. They can
  // disagree whenever the device pixel ratio changes without a resize, such as
  // when the window is dragged to a monitor with a different scale factor.
  glViewport(0, 0, static_cast<GLsizei>(m_width),
             static_cast<GLsizei>(m_height));

  GLfloat tmp[5];
  glGetFloatv(GL_COLOR_CLEAR_VALUE, tmp);
  glGetFloatv(GL_DEPTH_CLEAR_VALUE, tmp + 4);
  glClearColor(0.0, 0.0, 0.0, 0.0);
  glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
  glClearColor(tmp[0], tmp[1], tmp[2], tmp[3]);
  glClearDepth(tmp[4]);
}

void SolidPipeline::end(const Camera& camera)
{
  // Bind VAO for fullscreen quad (required for OpenGL Core Profile)
  glBindVertexArray(d->screenVAO);

  // Render the ambient occlusion term into its own buffer first, so the
  // compositing stage can blur away the kernel's sampling pattern. Skipped
  // entirely when ambient occlusion is off, since nothing would read it.
  if (m_aoEnabled) {
    glBindFramebuffer(GL_FRAMEBUFFER, d->aoFBO);
    GLenum aoBuffersList[1] = { GL_COLOR_ATTACHMENT0 };
    glDrawBuffers(1, aoBuffersList);
    glViewport(0, 0, static_cast<GLsizei>(m_width),
               static_cast<GLsizei>(m_height));
    // This target has no depth attachment, and the pass covers every pixel.
    glDisable(GL_DEPTH_TEST);

    d->aoStageShaders.bind();
    d->bindSampler("inDepthTex", d->depthTexture, TextureUnitDepth);
    d->aoStageShaders.setUniformValue("width", float(m_width));
    d->aoStageShaders.setUniformValue("height", float(m_height));
    d->aoStageShaders.setUniformValue("inAoStrength", m_aoStrength);
    glDrawArrays(GL_TRIANGLES, 0, 6);

    // The passes that follow this one still depend on depth testing.
    glEnable(GL_DEPTH_TEST);
  }

  // Draw to screen
  if (glIsFramebuffer(d->defaultFBO)) {
    glBindFramebuffer(GL_FRAMEBUFFER, d->defaultFBO);
    GLenum drawBuffersList[1] = { GL_COLOR_ATTACHMENT0 };
    glDrawBuffers(1, drawBuffersList);
  } else {
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glDrawBuffer(GL_BACK);
  }
  glViewport(d->defaultViewport[0], d->defaultViewport[1],
             d->defaultViewport[2], d->defaultViewport[3]);
  d->attachStage(d->firstStageShaders, "inRGBTex", d->renderTexture,
                 "inDepthTex", d->depthTexture, m_width, m_height);
  d->firstStageShaders.setUniformValue("inAoEnabled",
                                       m_aoEnabled ? 1.0f : 0.0f);
  d->firstStageShaders.setUniformValue("inDofEnabled",
                                       m_dofEnabled ? 1.0f : 0.0f);
  d->firstStageShaders.setUniformValue(
    "inDofStrength", m_dofEnabled ? (m_dofStrength * 100.0f) : 0.0f);
  d->firstStageShaders.setUniformValue("inDofPosition",
                                       ((m_dofPosition) / 10.0f));

  // The AO term, plus the projection the blur uses to read window depth back
  // as a distance in scene units.
  d->bindSampler("inAoTex", d->aoTexture, TextureUnitAo);
  d->firstStageShaders.setUniformValue("inProjection",
                                       camera.projection().matrix());
  d->firstStageShaders.setUniformValue("inEdStrength", m_edStrength);
  d->firstStageShaders.setUniformValue("inFogEnabled",
                                       m_fogEnabled ? 1.0f : 0.0f);
  d->firstStageShaders.setUniformValue("inFogStrength",
                                       m_fogEnabled ? m_fogStrength : 0.0f);
  d->firstStageShaders.setUniformValue("inFogPosition", m_fogPosition);
  d->firstStageShaders.setUniformValue("fogR", (m_backgroundColor[0]) / 255.0f);
  d->firstStageShaders.setUniformValue("fogG", (m_backgroundColor[1]) / 255.0f);
  d->firstStageShaders.setUniformValue("fogB", (m_backgroundColor[2]) / 255.0f);
  glDrawArrays(GL_TRIANGLES, 0, 6);
  glBindVertexArray(0);
}

void SolidPipeline::adjustOffset(const Camera& cam)
{

  // The numbers used in calculations are random.
  // They help define an offset with the projection-matrix
  // to make the fog dynamic as the molecule moves away
  // from the camera or come closer.
  Eigen::Matrix4f projectView = cam.projection().matrix();

  float project = ((((5000 + projectView(2, 3) * 1000) / 6) + 55) * 100);

  float offSet = 0.000102337 * pow(project, 2) - 3.84689 * project + 36182.2;
  if (project >= 21018.106 && project < 21595.588) {
    offSet = 2.63129 * project - 54768.4;
  } else if (project >= 21595.588) {
    offSet = 9.952 * project - 212865;
  }
  d->firstStageShaders.setUniformValue("uoffset", offSet);
}

void SolidPipeline::resize(int width, int height)
{
  m_width = width * m_pixelRatio;
  m_height = height * m_pixelRatio;

  glBindTexture(GL_TEXTURE_2D, d->renderTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, m_width, m_height, 0, GL_RGBA,
               GL_UNSIGNED_BYTE, nullptr);

  glBindTexture(GL_TEXTURE_2D, d->depthTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_DEPTH_COMPONENT, m_width, m_height, 0,
               GL_DEPTH_COMPONENT, GL_UNSIGNED_BYTE, nullptr);

  glBindTexture(GL_TEXTURE_2D, d->aoTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_R16F, m_width, m_height, 0, GL_RED,
               GL_FLOAT, nullptr);
}

void SolidPipeline::setPixelRatio(float ratio)
{
  m_pixelRatio = ratio;
}

} // End namespace Avogadro::Rendering
