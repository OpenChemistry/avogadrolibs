/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "volumegeometry.h"

#include "avogadrogl.h"
#include "bufferobject.h"
#include "camera.h"
#include "scene.h"
#include "shader.h"
#include "shaderprogram.h"
#include "visitor.h"

#include <string>
#include <fstream>
#include <sstream>
#include <iostream>

#include "volume_box_fs.h" //  bounding‐box fragment shader
#include "volume_box_vs.h" //  bounding‐box vertex shader
#include "volume_fs.h"     //  main volume fragment shader
#include "volume_vs.h"     //  main volume vertex shader

namespace Avogadro::Rendering {

namespace {
// A simple fullscreen quad (two triangles).
static const GLfloat s_fullscreenQuad[] = {
  -1.0f, -1.0f, 0.0f,   // Bottom-left
   1.0f, -1.0f, 0.0f,   // Bottom-right
  -1.0f,  1.0f, 0.0f,   // Top-left

  -1.0f,  1.0f, 0.0f,   // Top-left
   1.0f, -1.0f, 0.0f,   // Bottom-right
   1.0f,  1.0f, 0.0f    // Top-right
};

// A simple box (cube) for front/back passes
static const GLfloat boxVertices[] = {
  // x      y      z
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

void initializeFramebuffers(GLuint* outFBO, GLuint* texRGB, GLuint* texDepth,
                            int width, int height)
{
  // Log the actual size used here:
  std::cout << "Initializing FBO: " << width << " x " << height << std::endl;

  glGenFramebuffers(1, outFBO);
  glBindFramebuffer(GL_FRAMEBUFFER, *outFBO);

  // Color attachment.
  glGenTextures(1, texRGB);
  glBindTexture(GL_TEXTURE_2D, *texRGB);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, width, height, 0,
               GL_RGB, GL_UNSIGNED_BYTE, nullptr);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                         GL_TEXTURE_2D, *texRGB, 0);

  // Depth attachment.
  glGenTextures(1, texDepth);
  glBindTexture(GL_TEXTURE_2D, *texDepth);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glTexImage2D(GL_TEXTURE_2D, 0, GL_DEPTH_COMPONENT,
               width, height, 0,
               GL_DEPTH_COMPONENT, GL_FLOAT, nullptr);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT,
                         GL_TEXTURE_2D, *texDepth, 0);

  // Check for completeness.
  GLenum status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
  if (status != GL_FRAMEBUFFER_COMPLETE) {
    std::cerr << "Error: Framebuffer incomplete: 0x"
              << std::hex << status << std::endl;
  } else {
    std::cout << "Framebuffer complete.\n";
  }

  // Unbind the FBO:
  glBindFramebuffer(GL_FRAMEBUFFER, 0);
}

} // end anonymous namespace

class VolumeGeometry::Private
{
public:
  Private() : vertexShader(nullptr),
              fragmentShader(nullptr),
              program(nullptr),
              vao(0),
              vbo(0),
              defaultFBO(0),
              renderFBO(0),
              renderTexture(0),
              depthTexture(0),
              frontFBO(0),
              frontColorTexture(0),
              frontDepthTexture(0),
              backFBO(0),
              backColorTexture(0),
              backDepthTexture(0),
              boxVertexShader(nullptr),
              boxFragmentShader(nullptr),
              boxShaders(nullptr),
              transferTexture(0),
              volumeBoxVao(0),
              volumeBoxVbo(0),
              volumeBoxEbo(0),
              volumeTexture(0)
  { }

  // GL resources
  Shader* vertexShader;
  Shader* fragmentShader;
  ShaderProgram* program;

  GLuint vao;
  GLuint vbo;

  GLuint frontFBO;
  GLuint frontColorTexture;
  GLuint frontDepthTexture;

  GLuint backFBO;
  GLuint backColorTexture;
  GLuint backDepthTexture;

  Shader* boxVertexShader;
  Shader* boxFragmentShader;
  ShaderProgram* boxShaders;

  GLuint transferTexture;
  GLuint volumeBoxVao;
  GLuint volumeBoxVbo;
  GLuint volumeBoxEbo;
  GLuint volumeTexture;

  GLuint defaultFBO;
  GLuint renderFBO;
  GLuint renderTexture;
  GLuint depthTexture;
};

VolumeGeometry::VolumeGeometry()
  : m_cube(nullptr),
    m_dirty(true),
    m_positiveColor(255, 0, 0),
    m_negativeColor(0, 0, 255),
    d(new Private)
{
  m_width = 1000;
  m_height = 900;
}

VolumeGeometry::~VolumeGeometry()
{
  end();
  delete d;
}

VolumeGeometry::VolumeGeometry(const VolumeGeometry& other)
  : Drawable(other),
    m_positiveColor(other.m_positiveColor),
    m_negativeColor(other.m_negativeColor),
    m_cube(other.m_cube),
    m_dirty(other.m_dirty),
    d(new Private(*other.d)),
    m_width(other.m_width),
    m_height(other.m_height)
{
}

VolumeGeometry& VolumeGeometry::operator=(VolumeGeometry other)
{
  swap(*this, other);
  return *this;
}

void swap(VolumeGeometry& lhs, VolumeGeometry& rhs)
{
  using std::swap;
  swap(lhs.m_cube, rhs.m_cube);
  swap(lhs.m_dirty, rhs.m_dirty);
  swap(lhs.m_positiveColor, rhs.m_positiveColor);
  swap(lhs.m_negativeColor, rhs.m_negativeColor);
  swap(static_cast<Drawable&>(lhs), static_cast<Drawable&>(rhs));
  swap(lhs.d, rhs.d);
  // Fix the width/height swap bug:
  swap(lhs.m_width, rhs.m_width);
  swap(lhs.m_height, rhs.m_height);
}

void VolumeGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void VolumeGeometry::clear()
{
  m_cube = nullptr;
  m_dirty = true;
}

void VolumeGeometry::setCube(const Core::Cube& cube)
{
  m_cube = &cube;
  m_dirty = true;

  // Compute min/max from the raw volume data:
  Vector3f min = cube.min().cast<float>();
  Vector3f max = cube.max().cast<float>();
  m_boundingVertices[0] = min.x();
  m_boundingVertices[1] = min.y();
  m_boundingVertices[2] = max.z();

  m_boundingVertices[3] = max.x();
  m_boundingVertices[4] = min.y();
  m_boundingVertices[5] = max.z();

  m_boundingVertices[6] = max.x();
  m_boundingVertices[7] = max.y();
  m_boundingVertices[8] = max.z();

  m_boundingVertices[9] = min.x();
  m_boundingVertices[10] = max.y();
  m_boundingVertices[11] = max.z();

  // back face
  m_boundingVertices[12] = min.x();
  m_boundingVertices[13] = min.y();
  m_boundingVertices[14] = min.z();

  m_boundingVertices[15] = max.x();
  m_boundingVertices[16] = min.y();
  m_boundingVertices[17] = min.z();

  m_boundingVertices[18] = max.x();
  m_boundingVertices[19] = max.y();
  m_boundingVertices[20] = min.z();

  m_boundingVertices[21] = min.x();
  m_boundingVertices[22] = max.y();
  m_boundingVertices[23] = min.z();
}


void VolumeGeometry::resizeFBO(int newWidth, int newHeight)
{
  m_width = newWidth;
  m_height = newHeight;

  if (d->renderFBO) {
    glDeleteFramebuffers(1, &d->renderFBO);
    d->renderFBO = 0;
  }
  if (d->renderTexture) {
    glDeleteTextures(1, &d->renderTexture);
    d->renderTexture = 0;
  }
  if (d->depthTexture) {
    glDeleteTextures(1, &d->depthTexture);
    d->depthTexture = 0;
  }

  if (d->frontFBO) {
    glDeleteFramebuffers(1, &d->frontFBO);
    d->frontFBO = 0;
  }
  if (d->frontColorTexture) {
    glDeleteTextures(1, &d->frontColorTexture);
    d->frontColorTexture = 0;
  }
  if (d->frontDepthTexture) {
    glDeleteTextures(1, &d->frontDepthTexture);
    d->frontDepthTexture = 0;
  }

  if (d->backFBO) {
    glDeleteFramebuffers(1, &d->backFBO);
    d->backFBO = 0;
  }
  if (d->backColorTexture) {
    glDeleteTextures(1, &d->backColorTexture);
    d->backColorTexture = 0;
  }
  if (d->backDepthTexture) {
    glDeleteTextures(1, &d->backDepthTexture);
    d->backDepthTexture = 0;
  }

  initializeFramebuffers(&d->renderFBO, &d->renderTexture,
                         &d->depthTexture, m_width, m_height);

  initializeFramebuffers(&d->backFBO, &d->backColorTexture,
                         &d->backDepthTexture, m_width, m_height);

  initializeFramebuffers(&d->frontFBO, &d->frontColorTexture,
                         &d->frontDepthTexture, m_width, m_height);
}

void VolumeGeometry::initialize()
{
  if (!m_cube || !m_dirty)
    return;

  std::cout << "VolumeGeometry::initialize()\n";

  // ---------------------------------------------------------
  // CHANGED: Use a floating-point 3D texture (GL_R32F) so that
  //          negative values are preserved in wavefunction data.
  // ---------------------------------------------------------
  glGenTextures(1, &d->volumeTexture);
  glBindTexture(GL_TEXTURE_3D, d->volumeTexture);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_WRAP_R, GL_CLAMP_TO_EDGE);

  // Instead of 'GL_R8', do 'GL_R32F' with float data:
  glTexImage3D(GL_TEXTURE_3D, 0, GL_R32F,
               m_cube->nx(), m_cube->ny(), m_cube->nz(),
               0, GL_RED, GL_FLOAT,
               m_cube->data()->data());
  // ---------------------------------------------------------

  // Make a simple 1D transfer function. If you want to see negative vs.
  // positive distinctly, you'd create a more sophisticated one. For now,
  // this just goes from transparent black to opaque green:
  std::vector<unsigned char> tfData(256 * 4);
  for (int i = 0; i < 256; ++i) {
    float t = float(i) / 255.0f;
    tfData[i * 4 + 0] = static_cast<unsigned char>(0.0f);          // R
    tfData[i * 4 + 1] = static_cast<unsigned char>(255.0f * t);    // G
    tfData[i * 4 + 2] = static_cast<unsigned char>(0.0f);          // B
    tfData[i * 4 + 3] = static_cast<unsigned char>(255.0f * t);    // A
  }

  glGenTextures(1, &d->transferTexture);
  glBindTexture(GL_TEXTURE_2D, d->transferTexture);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 256, 1, 0,
               GL_RGBA, GL_UNSIGNED_BYTE, tfData.data());
  glBindTexture(GL_TEXTURE_2D, 0);

  // Box geometry for front/back pass
  glGenVertexArrays(1, &d->volumeBoxVao);
  glBindVertexArray(d->volumeBoxVao);

  glGenBuffers(1, &d->volumeBoxVbo);
  glBindBuffer(GL_ARRAY_BUFFER, d->volumeBoxVbo);
  glBufferData(GL_ARRAY_BUFFER, sizeof(boxVertices),
               boxVertices, GL_STATIC_DRAW);

  glEnableVertexAttribArray(0);
  glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE,
                        3 * sizeof(GLfloat), (GLvoid*)0);

  glGenBuffers(1, &d->volumeBoxEbo);
  glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, d->volumeBoxEbo);
  glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(boxIndices),
               boxIndices, GL_STATIC_DRAW);

  glBindVertexArray(0);

  // Fullscreen quad geometry
  glGenBuffers(1, &d->vbo);
  glBindBuffer(GL_ARRAY_BUFFER, d->vbo);
  glBufferData(GL_ARRAY_BUFFER, sizeof(s_fullscreenQuad),
               s_fullscreenQuad, GL_STATIC_DRAW);
  glBindBuffer(GL_ARRAY_BUFFER, 0);

  glGenVertexArrays(1, &d->vao);
  glBindVertexArray(d->vao);
  glBindBuffer(GL_ARRAY_BUFFER, d->vbo);
  glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE,
                        0, reinterpret_cast<void*>(0));
  glEnableVertexAttribArray(0);
  glBindVertexArray(0);

  // Create/resize FBOs
  resizeFBO(m_width, m_height);

  // Main volume shaders
  if (!d->vertexShader) {
    d->vertexShader = new Shader(Shader::Vertex);
    d->vertexShader->setSource(volume_vs);
    if (!d->vertexShader->compile())
      std::cerr << "VolumeGeometry: Vertex shader compile failed.\n";
  }

  if (!d->fragmentShader) {
    d->fragmentShader = new Shader(Shader::Fragment);
    d->fragmentShader->setSource(volume_fs);
    if (!d->fragmentShader->compile())
      std::cout << d->fragmentShader->error() << std::endl;
  }

  if (!d->program) {
    d->program = new ShaderProgram();
    d->program->attachShader(*d->vertexShader);
    d->program->attachShader(*d->fragmentShader);
    if (!d->program->link())
      std::cerr << "VolumeGeometry: Shader program linking failed.\n";
  }

  // Box pass shaders
  if (!d->boxVertexShader) {
    d->boxVertexShader = new Shader(Shader::Vertex);
    d->boxVertexShader->setSource(volume_box_vs);
    if (!d->boxVertexShader->compile())
      std::cerr << "VolumeGeometry: Box vertex shader compile failed.\n";
  }

  if (!d->boxFragmentShader) {
    d->boxFragmentShader = new Shader(Shader::Fragment);
    d->boxFragmentShader->setSource(volume_box_fs);
    if (!d->boxFragmentShader->compile())
      std::cerr << "VolumeGeometry: Box fragment shader compile failed.\n";
  }

  if (!d->boxShaders) {
    d->boxShaders = new ShaderProgram();
    d->boxShaders->attachShader(*d->boxVertexShader);
    d->boxShaders->attachShader(*d->boxFragmentShader);
    if (!d->boxShaders->link())
      std::cerr << "VolumeGeometry: Box shader program linking failed.\n";
  }

  m_dirty = false;
}

void VolumeGeometry::render(const Camera& camera)
{
  if (!m_cube)
    return;
  if (m_dirty)
    initialize();

  glGetIntegerv(GL_FRAMEBUFFER_BINDING, (GLint*)&d->defaultFBO);

  // 1) Copy default FBO into renderFBO
  glBindFramebuffer(GL_READ_FRAMEBUFFER, d->defaultFBO);
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, d->renderFBO);
  glBlitFramebuffer(0, 0, m_width, m_height,
                    0, 0, m_width, m_height,
                    GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT,
                    GL_NEAREST);

  // 2) Render the BACK faces of bounding box
  {
    glBindFramebuffer(GL_FRAMEBUFFER, d->backFBO);
    glViewport(0, 0, m_width, m_height);
    glEnable(GL_DEPTH_TEST);
    glEnable(GL_CULL_FACE);

    glCullFace(GL_FRONT);
    glClearColor(0.f, 0.f, 0.f, 0.f);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    d->boxShaders->bind();

    Eigen::Matrix4f mv = camera.modelView().matrix();
    Eigen::Matrix4f proj = camera.projection().matrix();
    Eigen::Matrix4f mvp = proj * mv;
    d->boxShaders->setUniformValue("uMVP", mvp);

    glBindVertexArray(d->volumeBoxVao);
    glDrawElements(GL_TRIANGLES, 36, GL_UNSIGNED_INT, 0);
    glBindVertexArray(0);

    d->boxShaders->release();

    glDisable(GL_CULL_FACE);
    glDisable(GL_DEPTH_TEST);
  }

  // 3) Render the FRONT faces of bounding box
  {
    glBindFramebuffer(GL_FRAMEBUFFER, d->frontFBO);
    glViewport(0, 0, m_width, m_height);
    glEnable(GL_DEPTH_TEST);
    glEnable(GL_CULL_FACE);

    glCullFace(GL_BACK);
    glClearColor(0.f, 0.f, 0.f, 0.f);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    d->boxShaders->bind();

    Eigen::Matrix4f mv = camera.modelView().matrix();
    Eigen::Matrix4f proj = camera.projection().matrix();
    Eigen::Matrix4f mvp = proj * mv;
    d->boxShaders->setUniformValue("uMVP", mvp);

    glBindVertexArray(d->volumeBoxVao);
    glDrawElements(GL_TRIANGLES, 36, GL_UNSIGNED_INT, 0);
    glBindVertexArray(0);

    d->boxShaders->release();

    glDisable(GL_CULL_FACE);
    glDisable(GL_DEPTH_TEST);
  }

  // 4) Final pass: ray marching
  glBindFramebuffer(GL_FRAMEBUFFER, d->defaultFBO);
  glViewport(0, 0, m_width, m_height);

  d->program->bind();

  GLint pId = 0;
  glGetIntegerv(GL_CURRENT_PROGRAM, &pId);

  // inRGBTex -> unit 0
  {
    GLint loc = glGetUniformLocation(pId, "inRGBTex");
    if (loc >= 0) {
      glActiveTexture(GL_TEXTURE0);
      glBindTexture(GL_TEXTURE_2D, d->renderTexture);
      glUniform1i(loc, 0);
    }
  }

  // inFrontPosTex -> unit 1
  {
    GLint loc = glGetUniformLocation(pId, "inFrontPosTex");
    if (loc >= 0) {
      glActiveTexture(GL_TEXTURE1);
      glBindTexture(GL_TEXTURE_2D, d->frontColorTexture);
      glUniform1i(loc, 1);
    }
  }

  // inBackPosTex -> unit 2
  {
    GLint loc = glGetUniformLocation(pId, "inBackPosTex");
    if (loc >= 0) {
      glActiveTexture(GL_TEXTURE2);
      glBindTexture(GL_TEXTURE_2D, d->backColorTexture);
      glUniform1i(loc, 2);
    }
  }

  // transferTex -> unit 3
  {
    GLint loc = glGetUniformLocation(pId, "transferTex");
    if (loc >= 0) {
      glActiveTexture(GL_TEXTURE3);
      glBindTexture(GL_TEXTURE_2D, d->transferTexture);
      glUniform1i(loc, 3);
    }
  }

  // uVolumeData -> unit 4
  {
    GLint loc = glGetUniformLocation(pId, "uVolumeData");
    if (loc >= 0) {
      glActiveTexture(GL_TEXTURE4);
      glBindTexture(GL_TEXTURE_3D, d->volumeTexture);
      glUniform1i(loc, 4);
    }
  }

  d->program->setUniformValue("width",  float(m_width));
  d->program->setUniformValue("height", float(m_height));
  d->program->setUniformValue("numSteps", 128);
  d->program->setUniformValue("alphaScale", 0.6f);

  glBindVertexArray(d->vao);
  glDrawArrays(GL_TRIANGLES, 0, 6);
  glBindVertexArray(0);

  d->program->release();
}

void VolumeGeometry::resize(int width, int height)
{
  if (width == m_width && height == m_height)
    return;
  resizeFBO(width, height);
}

void VolumeGeometry::end()
{
  if (d->vbo) {
    glDeleteBuffers(1, &d->vbo);
    d->vbo = 0;
  }
  if (d->vao) {
    glDeleteVertexArrays(1, &d->vao);
    d->vao = 0;
  }
  if (d->renderTexture) {
    glDeleteTextures(1, &d->renderTexture);
    d->renderTexture = 0;
  }
  if (d->depthTexture) {
    glDeleteTextures(1, &d->depthTexture);
    d->depthTexture = 0;
  }
  if (d->renderFBO) {
    glDeleteFramebuffers(1, &d->renderFBO);
    d->renderFBO = 0;
  }
  if (d->backFBO) {
    glDeleteFramebuffers(1, &d->backFBO);
    d->backFBO = 0;
  }
  if (d->backColorTexture) {
    glDeleteTextures(1, &d->backColorTexture);
    d->backColorTexture = 0;
  }
  if (d->backDepthTexture) {
    glDeleteTextures(1, &d->backDepthTexture);
    d->backDepthTexture = 0;
  }
  if (d->frontFBO) {
    glDeleteFramebuffers(1, &d->frontFBO);
    d->frontFBO = 0;
  }
  if (d->frontColorTexture) {
    glDeleteTextures(1, &d->frontColorTexture);
    d->frontColorTexture = 0;
  }
  if (d->frontDepthTexture) {
    glDeleteTextures(1, &d->frontDepthTexture);
    d->frontDepthTexture = 0;
  }
  if (d->volumeBoxVbo) {
    glDeleteBuffers(1, &d->volumeBoxVbo);
    d->volumeBoxVbo = 0;
  }
  if (d->volumeBoxEbo) {
    glDeleteBuffers(1, &d->volumeBoxEbo);
    d->volumeBoxEbo = 0;
  }
  if (d->volumeBoxVao) {
    glDeleteVertexArrays(1, &d->volumeBoxVao);
    d->volumeBoxVao = 0;
  }
  if (d->volumeTexture) {
    glDeleteTextures(1, &d->volumeTexture);
    d->volumeTexture = 0;
  }
  if (d->transferTexture) {
    glDeleteTextures(1, &d->transferTexture);
    d->transferTexture = 0;
  }

  if (d->boxShaders) {
    delete d->boxShaders;
    d->boxShaders = nullptr;
  }
  if (d->boxVertexShader) {
    delete d->boxVertexShader;
    d->boxVertexShader = nullptr;
  }
  if (d->boxFragmentShader) {
    delete d->boxFragmentShader;
    d->boxFragmentShader = nullptr;
  }

  if (d->program) {
    delete d->program;
    d->program = nullptr;
  }
  if (d->vertexShader) {
    delete d->vertexShader;
    d->vertexShader = nullptr;
  }
  if (d->fragmentShader) {
    delete d->fragmentShader;
    d->fragmentShader = nullptr;
  }
}

} // End namespace Avogadro::Rendering
