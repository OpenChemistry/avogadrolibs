/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "solidpipeline.h"

#include "avogadrogl.h"
#include "shader.h"
#include "shaderprogram.h"

// Box pass ke liye simple vertex shader (neeche define kiya hai)
#include "solidBox_vs.h"
#include "solidBox_fs.h"

// Tumhara fullscreen pass vertex shader (jo Quad ke liye use hota hai)
#include "solid_vs.h"
#include "solid_first_fs.h"

#include <avogadro/core/cube.h>
#include "camera.h"

#include <iostream>
#include <vector>
#include <cmath>
#include <algorithm> // for clamp

namespace Avogadro::Rendering {

class SolidPipeline::Private
{
public:
  Private() {}

  /** Attach the main scene stage (color+depth). */
  void attachStage(ShaderProgram& prog,
                   const GLchar* nameRGB,   GLuint texRGB,
                   const GLchar* nameDepth, GLuint texDepth,
                   int w, int h)
  {
    prog.bind();
    GLuint programID;
    glGetIntegerv(GL_CURRENT_PROGRAM, (GLint*)&programID);

    // Scene color
    GLuint attrRGB = glGetUniformLocation(programID, nameRGB);
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, texRGB);
    glUniform1i(attrRGB, 1);

    // Scene depth
    GLuint attrDepth = glGetUniformLocation(programID, nameDepth);
    glActiveTexture(GL_TEXTURE2);
    glBindTexture(GL_TEXTURE_2D, texDepth);
    glUniform1i(attrDepth, 2);

    // Pass screen size
    prog.setUniformValue("width",  float(w));
    prog.setUniformValue("height", float(h));
  }

  /** Attach front/back depth passes for the volume bounding box. */
  void attachVolumeStage(ShaderProgram& prog,
                         const GLchar* frontDepthName, GLuint frontDepthTex,
                         const GLchar* backDepthName,  GLuint backDepthTex,
                         int w, int h)
  {
    prog.bind();
    GLuint programID;
    glGetIntegerv(GL_CURRENT_PROGRAM, (GLint*)&programID);

    // Front face depth
    GLuint frontLoc = glGetUniformLocation(programID, frontDepthName);
    glActiveTexture(GL_TEXTURE4);
    glBindTexture(GL_TEXTURE_2D, frontDepthTex);
    glUniform1i(frontLoc, 4);

    // Back face depth
    GLuint backLoc = glGetUniformLocation(programID, backDepthName);
    glActiveTexture(GL_TEXTURE5);
    glBindTexture(GL_TEXTURE_2D, backDepthTex);
    glUniform1i(backLoc, 5);

    // Pass screen size
    // prog.setUniformValue("width",  float(w));
    // prog.setUniformValue("height", float(h));
  }

  void attachTransferFunction(ShaderProgram& prog,
                              const GLchar* tfName, GLuint tfTex)
  {
    prog.bind();
    GLuint programID = 0;
    glGetIntegerv(GL_CURRENT_PROGRAM, (GLint*)&programID);

    // Bind the transfer function texture on some texture unit (say GL_TEXTURE6)
    GLuint loc = glGetUniformLocation(programID, tfName);
    glActiveTexture(GL_TEXTURE6);
    glBindTexture(GL_TEXTURE_2D, tfTex);
    glUniform1i(loc, 6); // tell the sampler that our TF is at unit 6
  }
  
  /** Our FBOs and textures. */
  GLuint defaultFBO;       // The system FBO (screen)
  GLuint renderFBO;        // Main scene FBO
  GLuint renderTexture;    // Main scene color
  GLuint depthTexture;     // Main scene depth

  // Front/back passes
  GLuint frontFBO;
  GLuint frontColorTexture;
  GLuint frontDepthTexture;

  GLuint backFBO;
  GLuint backColorTexture;
  GLuint backDepthTexture;

  // Volume rendering data
  GLuint volumeTexture;    // 3D volume
  GLuint screenVBO;        // Fullscreen quad VBO

  // Shaders
  ShaderProgram boxShaders;       // <-- For drawing the bounding box
  Shader boxVertexShader;
  Shader boxFragmentShader;

  ShaderProgram firstStageShaders; // <-- For compositing
  Shader screenVertexShader;
  Shader firstFragmentShader;

  // Box geometry for front/back pass
  GLuint transferTexture;
  GLuint volumeBoxVao;
  GLuint volumeBoxVbo;
  GLuint volumeBoxEbo;
};

// Fullscreen quad vertices
static const GLfloat s_fullscreenQuad[] = {
  -1.f, -1.f, 0.f,
   1.f, -1.f, 0.f,
  -1.f,  1.f, 0.f,

  -1.f,  1.f, 0.f,
   1.f, -1.f, 0.f,
   1.f,  1.f, 0.f,
};

// A simple cube bounding box
static const GLfloat boxVertices[] = {
  //    x     y     z
  // Front face
  -1.0f, -1.0f,  1.0f,
   1.0f, -1.0f,  1.0f,
   1.0f,  1.0f,  1.0f,
  -1.0f,  1.0f,  1.0f,

  // Back face
  -1.0f, -1.0f, -1.0f,
   1.0f, -1.0f, -1.0f,
   1.0f,  1.0f, -1.0f,
  -1.0f,  1.0f, -1.0f,
};

static const GLuint boxIndices[] = {
              // front
              0, 1, 2,
              0, 2, 3,
              // right
              1, 5, 6,
              1, 6, 2,
              // back
              5, 4, 7,
              5, 7, 6,
              // left
              4, 0, 3,
              4, 3, 7,
              // top
              2, 6, 7,
              2, 7, 3,
              // bottom
              4, 5, 1,
              4, 1, 0,
};

// Helper to create an FBO
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
  : m_pixelRatio(1.0f),
    m_aoEnabled(true),
    m_aoStrength(1.0f),
    m_edEnabled(true),
    m_edStrength(1.0f),
    m_width(0),
    m_height(0),
    d(new Private)
{
}

SolidPipeline::~SolidPipeline()
{
    if (d->transferTexture) {
    glDeleteTextures(1, &d->transferTexture);
    d->transferTexture = 0;
  }
  delete d;
}

void SolidPipeline::initialize()
{
  std::cout<<"SolidPipeline::initialize()"<<std::endl;
  // 1) Create FBOs
  initializeFramebuffer(&d->renderFBO, &d->renderTexture, &d->depthTexture);
  initializeFramebuffer(&d->backFBO,   &d->backColorTexture, &d->backDepthTexture);
  initializeFramebuffer(&d->frontFBO,  &d->frontColorTexture,&d->frontDepthTexture);

  // 2) Make a 3D volume texture
  glGenTextures(1, &d->volumeTexture);
  glBindTexture(GL_TEXTURE_3D, d->volumeTexture);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_WRAP_R, GL_CLAMP_TO_EDGE);

  int size = 256;
  std::vector<float> volumeData(size * size * size, 0.0f);
  for (int z = 0; z < size; ++z) {
    for (int y = 0; y < size; ++y) {
      for (int x = 0; x < size; ++x) {
        float dx = (x - size / 2.0f) / (size / 2.0f);
        float dy = (y - size / 2.0f) / (size / 2.0f);
        float dz = (z - size / 2.0f) / (size / 2.0f);
        float dist = std::sqrt(dx*dx + dy*dy + dz*dz);
        volumeData[z*size*size + y*size + x] = std::exp(-3.0f * dist);
      }
    }
  }

  glTexImage3D(GL_TEXTURE_3D, 0, GL_R32F,
               size, size, size, 0,
               GL_RED, GL_FLOAT,
               volumeData.data());
  std::vector<unsigned char> tfData(256 * 4);
  for (int i = 0; i < 256; ++i) {
    // i ko [0..255] se normalize karke color aur alpha define
    float t = float(i) / 255.0f;
    // let’s do a pinkish gradient: RGBA
    tfData[i*4 + 0] = static_cast<unsigned char>(255.0f * t);    // R
    tfData[i*4 + 1] = static_cast<unsigned char>(128.0f * t);    // G
    tfData[i*4 + 2] = static_cast<unsigned char>(255.0f * (1-t));// B
    tfData[i*4 + 3] = static_cast<unsigned char>(255.0f * t);    // A
  }

  glGenTextures(1, &d->transferTexture);
  glBindTexture(GL_TEXTURE_2D, d->transferTexture);

  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

  // Upload 256x1 RGBA8
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 256, 1, 0,
               GL_RGBA, GL_UNSIGNED_BYTE, tfData.data());
  glBindTexture(GL_TEXTURE_2D, 0);
  // 3) Create box geometry VAO
  glGenVertexArrays(1, &d->volumeBoxVao);
  glBindVertexArray(d->volumeBoxVao);

  glGenBuffers(1, &d->volumeBoxVbo);
  glBindBuffer(GL_ARRAY_BUFFER, d->volumeBoxVbo);
  glBufferData(GL_ARRAY_BUFFER, sizeof(boxVertices),
               boxVertices, GL_STATIC_DRAW);

  glEnableVertexAttribArray(0);
  glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE,
                        3*sizeof(GLfloat), (GLvoid*)0);

  glGenBuffers(1, &d->volumeBoxEbo);
  glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, d->volumeBoxEbo);
  glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(boxIndices),
               boxIndices, GL_STATIC_DRAW);

  glBindVertexArray(0);

  // 4) Fullscreen quad
  glGenBuffers(1, &d->screenVBO);
  glBindBuffer(GL_ARRAY_BUFFER, d->screenVBO);
  glBufferData(GL_ARRAY_BUFFER, sizeof(s_fullscreenQuad),
               s_fullscreenQuad, GL_STATIC_DRAW);
  glBindBuffer(GL_ARRAY_BUFFER, 0);

  // 5) Box pass ke liye simple shaders
  d->boxVertexShader.setType(Shader::Vertex);
  d->boxVertexShader.setSource(solidBox_vs);  // string with simple VS
  if (!d->boxVertexShader.compile())
    std::cerr << d->boxVertexShader.error() << std::endl;

  d->boxFragmentShader.setType(Shader::Fragment);
  d->boxFragmentShader.setSource(solidBox_fs); // string with simple FS
  if (!d->boxFragmentShader.compile())
    std::cerr << d->boxFragmentShader.error() << std::endl;

  d->boxShaders.attachShader(d->boxVertexShader);
  d->boxShaders.attachShader(d->boxFragmentShader);
  if (!d->boxShaders.link())
    std::cerr << d->boxShaders.error() << std::endl;

  // 6) Fullscreen pass (tumhare hi vs + fs)
  d->screenVertexShader.setType(Shader::Vertex);
  d->screenVertexShader.setSource(solid_vs);
  if (!d->screenVertexShader.compile())
    std::cerr << d->screenVertexShader.error() << std::endl;

  d->firstFragmentShader.setType(Shader::Fragment);
  d->firstFragmentShader.setSource(solid_first_fs);
  if (!d->firstFragmentShader.compile())
    std::cerr << d->firstFragmentShader.error() << std::endl;

  d->firstStageShaders.attachShader(d->screenVertexShader);
  d->firstStageShaders.attachShader(d->firstFragmentShader);
  if (!d->firstStageShaders.link())
    std::cerr << d->firstStageShaders.error() << std::endl;
}

void SolidPipeline::renderVolumeFaces(const Camera& cam)
{
  // Simple approach: use boxShaders to set up MVP

  d->boxShaders.bind();

  // Get the combined projection * modelView
  Eigen::Matrix4f projView = cam.projection().matrix() * cam.modelView().matrix();
  d->boxShaders.setUniformValue("uMVP", projView);

  // BACK FACES
  glBindFramebuffer(GL_FRAMEBUFFER, d->backFBO);
  {
    GLenum drawBuffersList[1] = { GL_COLOR_ATTACHMENT0 };
    glDrawBuffers(1, drawBuffersList);

    glViewport(0, 0, m_width, m_height);
    glEnable(GL_DEPTH_TEST);
    glEnable(GL_CULL_FACE);
    // glDepthFunc(GL_GREATER);
    glCullFace(GL_FRONT); // cull front, show back
    glClearColor(0.f, 0.f, 0.f, 0.f);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    glBindVertexArray(d->volumeBoxVao);
    glDrawElements(GL_TRIANGLES, 36, GL_UNSIGNED_INT, 0);
    glBindVertexArray(0);

    glDisable(GL_CULL_FACE);
    glDisable(GL_DEPTH_TEST);
  }

  // FRONT FACES
  glBindFramebuffer(GL_FRAMEBUFFER, d->frontFBO);
  {
    GLenum drawBuffersList[1] = { GL_COLOR_ATTACHMENT0 };
    glDrawBuffers(1, drawBuffersList);

    glViewport(0, 0, m_width, m_height);
    glEnable(GL_DEPTH_TEST);
    glEnable(GL_CULL_FACE);
    // glDepthFunc(GL_LESS);
    glCullFace(GL_BACK); // cull back, show front
    glClearColor(0.f, 0.f, 0.f, 0.f);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    glBindVertexArray(d->volumeBoxVao);
    glDrawElements(GL_TRIANGLES, 36, GL_UNSIGNED_INT, 0);
    glBindVertexArray(0);

    glDisable(GL_CULL_FACE);
    glDisable(GL_DEPTH_TEST);
  }

  glUseProgram(0);
}

void SolidPipeline::begin()
{
  // Save default FBO
  glGetIntegerv(GL_FRAMEBUFFER_BINDING, (GLint*)&d->defaultFBO);

  // Bind main scene FBO
  glBindFramebuffer(GL_FRAMEBUFFER, d->renderFBO);
  GLenum drawBuffersList[1] = { GL_COLOR_ATTACHMENT0 };
  glDrawBuffers(1, drawBuffersList);

  // Clear
  GLfloat oldClearColor[4];
  glGetFloatv(GL_COLOR_CLEAR_VALUE, oldClearColor);
  GLfloat oldDepthClear;
  glGetFloatv(GL_DEPTH_CLEAR_VALUE, &oldDepthClear);

  glClearColor(0.0, 0.0, 0.0, 0.0);
  glClearDepth(1.0f);
  glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

  // Restore old clear color
  glClearColor(oldClearColor[0], oldClearColor[1],
               oldClearColor[2], oldClearColor[3]);
  glClearDepth(oldDepthClear);

  // Enable blending + depth
  glEnable(GL_BLEND);
  glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
  glEnable(GL_DEPTH_TEST);
}

void SolidPipeline::end()
{
  // Bind default FBO again
  if (glIsFramebuffer(d->defaultFBO)) {
    glBindFramebuffer(GL_FRAMEBUFFER, d->defaultFBO);
    GLenum drawBuffersList[1] = { GL_COLOR_ATTACHMENT0 };
    glDrawBuffers(1, drawBuffersList);
  }
  else {
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glDrawBuffer(GL_BACK);
  }

  // Composite pass
  d->attachStage(d->firstStageShaders,
                 "inRGBTex",   d->renderTexture,
                 "inDepthTex", d->depthTexture,
                 m_width, m_height);

  d->attachVolumeStage(d->firstStageShaders,
                       "inFrontDepthTex", d->frontDepthTexture,
                       "inBackDepthTex",  d->backDepthTexture,
                       m_width, m_height);

  d->attachTransferFunction(d->firstStageShaders, "transferTex", d->transferTexture);
  d->firstStageShaders.bind();
  // Basic user uniforms
  d->firstStageShaders.setUniformValue("inAoEnabled",  (m_aoEnabled ? 1.0f : 0.0f));
  d->firstStageShaders.setUniformValue("inAoStrength", m_aoStrength);
  d->firstStageShaders.setUniformValue("inEdStrength", m_edStrength);
  d->firstStageShaders.setUniformValue("transferMin",  0.0f);
  d->firstStageShaders.setUniformValue("transferMax",  1.0f);
  d->firstStageShaders.setUniformValue("numSteps",     128);
  d->firstStageShaders.setUniformValue("alphaScale",   0.1f);

  // Bind volume
  GLint progID = 0;
  glGetIntegerv(GL_CURRENT_PROGRAM, &progID);
  GLint volLoc = glGetUniformLocation(progID, "uVolumeData");
  if (volLoc >= 0) {
    glActiveTexture(GL_TEXTURE3);
    glBindTexture(GL_TEXTURE_3D, d->volumeTexture);
    glUniform1i(volLoc, 3);
  }

  // Fullscreen quad
  glBindBuffer(GL_ARRAY_BUFFER, d->screenVBO);
  glEnableVertexAttribArray(0);
  glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE,
                        3*sizeof(GLfloat), (GLvoid*)0);

  glDrawArrays(GL_TRIANGLES, 0, 6);

  glDisableVertexAttribArray(0);
  glBindBuffer(GL_ARRAY_BUFFER, 0);
  glUseProgram(0);
}

void SolidPipeline::resize(int width, int height)
{
  m_width  = static_cast<int>(width  * m_pixelRatio);
  m_height = static_cast<int>(height * m_pixelRatio);

  // Re-allocate FBO textures
  glBindTexture(GL_TEXTURE_2D, d->renderTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, m_width, m_height, 0,
               GL_RGBA, GL_UNSIGNED_BYTE, nullptr);

  glBindTexture(GL_TEXTURE_2D, d->depthTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_DEPTH_COMPONENT24, m_width, m_height, 0,
               GL_DEPTH_COMPONENT, GL_UNSIGNED_INT, nullptr);

  glBindTexture(GL_TEXTURE_2D, d->backColorTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, m_width, m_height, 0,
               GL_RGBA, GL_UNSIGNED_BYTE, nullptr);

  glBindTexture(GL_TEXTURE_2D, d->backDepthTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_DEPTH_COMPONENT24, m_width, m_height, 0,
               GL_DEPTH_COMPONENT, GL_UNSIGNED_INT, nullptr);

  glBindTexture(GL_TEXTURE_2D, d->frontColorTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, m_width, m_height, 0,
               GL_RGBA, GL_UNSIGNED_BYTE, nullptr);

  glBindTexture(GL_TEXTURE_2D, d->frontDepthTexture);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_DEPTH_COMPONENT24, m_width, m_height, 0,
               GL_DEPTH_COMPONENT, GL_UNSIGNED_INT, nullptr);
}

void SolidPipeline::adjustOffset(const Camera& cam)
{
  // Yeh function agar tumhe extra uniform set karni ho to use karo
  // Warna abhi ke liye zyada zaroorat nahi, kyunki volume faces ke liye
  // main alag se MVP pass kar raha hoon (renderVolumeFaces()) mein.
  //
  // Example:
  // Eigen::Matrix4f projectView = cam.projection().matrix() * cam.modelView().matrix();
  // d->firstStageShaders.setUniformValue("uPV", projectView);
}

void SolidPipeline::setPixelRatio(float ratio)
{
  m_pixelRatio = ratio;
}

} // end namespace

