/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "volumegeometry.h"

#include "avogadrogl.h"
#include "blendstateguard_p.h"
#include "camera.h"
#include "shader.h"
#include "shaderprogram.h"
#include "visitor.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <memory>
#include <vector>

namespace {
#include "volume_fs.h"
#include "volume_vs.h"
} // namespace

namespace Avogadro::Rendering {

namespace {

constexpr int TextureUnitVolume = 0;
constexpr int TextureUnitSceneDepth = 1;

struct DepthAttachmentFormat
{
  GLint internalFormat = GL_DEPTH_COMPONENT24;
  GLenum format = GL_DEPTH_COMPONENT;
  GLenum type = GL_UNSIGNED_INT;

  bool operator==(const DepthAttachmentFormat& other) const
  {
    return internalFormat == other.internalFormat && format == other.format &&
           type == other.type;
  }
  bool operator!=(const DepthAttachmentFormat& other) const
  {
    return !(*this == other);
  }
};

// Query the currently bound read framebuffer's depth/stencil configuration so
// the depth-copy texture matches it (required for glBlitFramebuffer on WebGL 2
// and strict desktop drivers).
DepthAttachmentFormat detectDepthFormat(GLuint readFBO)
{
  DepthAttachmentFormat fmt;
  GLint depthSize = 0;
  GLint stencilSize = 0;
  GLint depthType = GL_UNSIGNED_NORMALIZED;

  if (readFBO == 0) {
    glGetFramebufferAttachmentParameteriv(GL_READ_FRAMEBUFFER, GL_DEPTH,
                                          GL_FRAMEBUFFER_ATTACHMENT_DEPTH_SIZE,
                                          &depthSize);
    glGetFramebufferAttachmentParameteriv(
      GL_READ_FRAMEBUFFER, GL_STENCIL, GL_FRAMEBUFFER_ATTACHMENT_STENCIL_SIZE,
      &stencilSize);
    glGetFramebufferAttachmentParameteriv(
      GL_READ_FRAMEBUFFER, GL_DEPTH, GL_FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE,
      &depthType);
  } else {
    GLint depthObj = GL_NONE;
    glGetFramebufferAttachmentParameteriv(
      GL_READ_FRAMEBUFFER, GL_DEPTH_ATTACHMENT,
      GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE, &depthObj);
    if (depthObj != GL_NONE) {
      glGetFramebufferAttachmentParameteriv(
        GL_READ_FRAMEBUFFER, GL_DEPTH_ATTACHMENT,
        GL_FRAMEBUFFER_ATTACHMENT_DEPTH_SIZE, &depthSize);
      glGetFramebufferAttachmentParameteriv(
        GL_READ_FRAMEBUFFER, GL_DEPTH_ATTACHMENT,
        GL_FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE, &depthType);
    }
    GLint stencilObj = GL_NONE;
    glGetFramebufferAttachmentParameteriv(
      GL_READ_FRAMEBUFFER, GL_STENCIL_ATTACHMENT,
      GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE, &stencilObj);
    if (stencilObj != GL_NONE) {
      glGetFramebufferAttachmentParameteriv(
        GL_READ_FRAMEBUFFER, GL_STENCIL_ATTACHMENT,
        GL_FRAMEBUFFER_ATTACHMENT_STENCIL_SIZE, &stencilSize);
    }
  }
  // Drain any GL error from querying an absent attachment (e.g. stencil on a
  // depth-only FBO).
  for (int i = 0; i < 8 && glGetError() != GL_NO_ERROR; ++i) {}

  const bool isFloat = (depthType == GL_FLOAT);
  if (stencilSize > 0) {
    if (isFloat) {
      fmt.internalFormat = GL_DEPTH32F_STENCIL8;
      fmt.format = GL_DEPTH_STENCIL;
      fmt.type = GL_FLOAT_32_UNSIGNED_INT_24_8_REV;
    } else {
      fmt.internalFormat = GL_DEPTH24_STENCIL8;
      fmt.format = GL_DEPTH_STENCIL;
      fmt.type = GL_UNSIGNED_INT_24_8;
    }
  } else if (isFloat) {
    fmt.internalFormat = GL_DEPTH_COMPONENT32F;
    fmt.format = GL_DEPTH_COMPONENT;
    fmt.type = GL_FLOAT;
  } else if (depthSize == 16) {
    fmt.internalFormat = GL_DEPTH_COMPONENT16;
    fmt.format = GL_DEPTH_COMPONENT;
    fmt.type = GL_UNSIGNED_SHORT;
  } else {
    fmt.internalFormat = GL_DEPTH_COMPONENT24;
    fmt.format = GL_DEPTH_COMPONENT;
    fmt.type = GL_UNSIGNED_INT;
  }
  return fmt;
}

} // namespace

class VolumeGeometry::Private
{
public:
  Private() = default;

  std::unique_ptr<Shader> vertexShader;
  std::unique_ptr<Shader> fragmentShader;
  std::unique_ptr<ShaderProgram> program;

  // Empty VAO for the procedural fullscreen triangle (required by Core
  // Profile).
  GLuint vao = 0;
  GLuint volumeTexture = 0;

  // Single-attachment FBO used to snapshot the opaque scene's depth buffer via
  // glBlitFramebuffer so volume raymarching can stop at atoms and bonds.
  GLuint depthCopyFBO = 0;
  GLuint depthCopyTexture = 0;
  DepthAttachmentFormat depthFormat;
  bool depthCopyReady = false;
};

VolumeGeometry::VolumeGeometry()
  : m_positiveColor(255, 0, 0), m_negativeColor(0, 0, 255), m_cube(nullptr),
    m_dirty(true), d(new Private), m_width(0), m_height(0)
{
}

VolumeGeometry::~VolumeGeometry()
{
  end();
  delete d;
}

VolumeGeometry::VolumeGeometry(const VolumeGeometry& other)
  : Drawable(other), m_positiveColor(other.m_positiveColor),
    m_negativeColor(other.m_negativeColor), m_cube(other.m_cube),
    m_alphaScale(other.m_alphaScale), m_dirty(true), d(new Private), m_width(0),
    m_height(0)
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
  swap(lhs.m_alphaScale, rhs.m_alphaScale);
  swap(lhs.m_dirty, rhs.m_dirty);
  swap(lhs.m_positiveColor, rhs.m_positiveColor);
  swap(lhs.m_negativeColor, rhs.m_negativeColor);
  swap(static_cast<Drawable&>(lhs), static_cast<Drawable&>(rhs));
  swap(lhs.d, rhs.d);
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
}

void VolumeGeometry::setAlphaScale(float scale)
{
  if (std::isnan(scale))
    return;
  m_alphaScale = std::max(scale, 0.0f);
}

void VolumeGeometry::resizeFBO(int newWidth, int newHeight)
{
  m_width = newWidth;
  m_height = newHeight;
  d->depthCopyReady = false;

  if (m_width <= 0 || m_height <= 0)
    return;

  GLint previousDrawFBO = 0;
  GLint previousReadFBO = 0;
  glGetIntegerv(GL_DRAW_FRAMEBUFFER_BINDING, &previousDrawFBO);
  glGetIntegerv(GL_READ_FRAMEBUFFER_BINDING, &previousReadFBO);

  if (d->depthCopyFBO == 0)
    glGenFramebuffers(1, &d->depthCopyFBO);
  if (d->depthCopyTexture == 0)
    glGenTextures(1, &d->depthCopyTexture);

  glBindTexture(GL_TEXTURE_2D, d->depthCopyTexture);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glTexImage2D(GL_TEXTURE_2D, 0, d->depthFormat.internalFormat, m_width,
               m_height, 0, d->depthFormat.format, d->depthFormat.type,
               nullptr);

  // Bind both read and draw targets to depthCopyFBO so glReadBuffer(GL_NONE)
  // applies to depthCopyFBO and never mutates the caller's read framebuffer.
  glBindFramebuffer(GL_FRAMEBUFFER, d->depthCopyFBO);
  const GLenum attachment = (d->depthFormat.format == GL_DEPTH_STENCIL)
                              ? GL_DEPTH_STENCIL_ATTACHMENT
                              : GL_DEPTH_ATTACHMENT;
  // Clear whichever attachment might have been bound previously if the format
  // switched between depth-only and depth-stencil.
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_STENCIL_ATTACHMENT,
                         GL_TEXTURE_2D, 0, 0);
  glFramebufferTexture2D(GL_FRAMEBUFFER, attachment, GL_TEXTURE_2D,
                         d->depthCopyTexture, 0);
  const GLenum none = GL_NONE;
  glDrawBuffers(1, &none);
  glReadBuffer(GL_NONE);

  d->depthCopyReady =
    (glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE);

  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, static_cast<GLuint>(previousDrawFBO));
  glBindFramebuffer(GL_READ_FRAMEBUFFER, static_cast<GLuint>(previousReadFBO));
}

void VolumeGeometry::initialize()
{
  if (!m_cube || !m_dirty)
    return;

  const int nx = m_cube->nx();
  const int ny = m_cube->ny();
  const int nz = m_cube->nz();
  if (nx <= 0 || ny <= 0 || nz <= 0 || !m_cube->data() ||
      m_cube->data()->size() < static_cast<size_t>(nx) *
                                 static_cast<size_t>(ny) *
                                 static_cast<size_t>(nz)) {
    m_dirty = false;
    return;
  }

  // Reorder cube data from z-fastest to x-fastest for 3D texture upload.
  std::vector<float> volumeData(static_cast<size_t>(nx) *
                                static_cast<size_t>(ny) *
                                static_cast<size_t>(nz));
  const float* src = m_cube->data()->data();
  for (int z = 0; z < nz; ++z) {
    for (int y = 0; y < ny; ++y) {
      for (int x = 0; x < nx; ++x) {
        const size_t oldIndex = static_cast<size_t>(z + nz * (y + ny * x));
        const size_t newIndex = static_cast<size_t>(x + nx * (y + ny * z));
        volumeData[newIndex] = src[oldIndex];
      }
    }
  }

  if (d->volumeTexture == 0)
    glGenTextures(1, &d->volumeTexture);
  glBindTexture(GL_TEXTURE_3D, d->volumeTexture);
  glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_3D, GL_TEXTURE_WRAP_R, GL_CLAMP_TO_EDGE);
  glTexImage3D(GL_TEXTURE_3D, 0, GL_R32F, nx, ny, nz, 0, GL_RED, GL_FLOAT,
               volumeData.data());

  if (d->vao == 0)
    glGenVertexArrays(1, &d->vao);

  if (!d->program) {
    d->vertexShader = std::make_unique<Shader>(Shader::Vertex, volume_vs);
    if (!d->vertexShader->compile())
      std::cerr << "VolumeGeometry: " << d->vertexShader->error() << '\n';

    d->fragmentShader = std::make_unique<Shader>(Shader::Fragment, volume_fs);
    if (!d->fragmentShader->compile())
      std::cerr << "VolumeGeometry: " << d->fragmentShader->error() << '\n';

    d->program = std::make_unique<ShaderProgram>();
    d->program->attachShader(*d->vertexShader);
    d->program->attachShader(*d->fragmentShader);
    if (!d->program->link())
      std::cerr << "VolumeGeometry: " << d->program->error() << '\n';
  }

  m_dirty = false;
}

void VolumeGeometry::render(const Camera& camera)
{
  if (!m_cube)
    return;

  // The box the volume fills in world space: the unit cube [0,1]^3 (the
  // texture coordinates) maps to origin + S * diag(n - 1) * u. It is a
  // parallelepiped for a skewed grid.
  const Eigen::Vector3d extent(m_cube->nx() - 1, m_cube->ny() - 1,
                               m_cube->nz() - 1);
  const Eigen::Matrix3d linear = m_cube->steps() * extent.asDiagonal();
  Eigen::Matrix4d boxD = Eigen::Matrix4d::Identity();
  boxD.block<3, 3>(0, 0) = linear;
  boxD.block<3, 1>(0, 3) = m_cube->min();
  const Eigen::Matrix4f boxInverse = boxD.inverse().cast<float>();
  if (!boxInverse.allFinite())
    return;

  // Inverse of (projection * modelView) in double precision for accurate
  // screen-ray unprojection across wide depth ranges.
  const Eigen::Matrix4d viewProjD =
    camera.projection().matrix().cast<double>() *
    camera.modelView().matrix().cast<double>();
  const Eigen::Matrix4f invViewProj = viewProjD.inverse().cast<float>();
  if (!invViewProj.allFinite())
    return;

  // Longest of the four body diagonals sets the world-space step scale.
  float boxDiagonal = 0.0f;
  for (int corner = 0; corner < 4; ++corner) {
    Eigen::Vector3d u((corner & 1) ? -1.0 : 1.0, (corner & 2) ? -1.0 : 1.0,
                      1.0);
    boxDiagonal =
      std::max(boxDiagonal, static_cast<float>((linear * u).norm()));
  }
  if (!(boxDiagonal > 0.0f))
    return;

  if (m_dirty)
    initialize();

  if (d->volumeTexture == 0 || !d->program || d->vao == 0)
    return;

  GLint activeFBO = 0;
  GLint previousReadFBO = 0;
  glGetIntegerv(GL_DRAW_FRAMEBUFFER_BINDING, &activeFBO);
  glGetIntegerv(GL_READ_FRAMEBUFFER_BINDING, &previousReadFBO);
  GLint vp[4] = { 0, 0, 0, 0 };
  glGetIntegerv(GL_VIEWPORT, vp);
  const int vpX = vp[0];
  const int vpY = vp[1];
  const int vpW = vp[2];
  const int vpH = vp[3];
  if (vpW <= 0 || vpH <= 0)
    return;

  // Snapshot the active framebuffer's depth buffer so opaque atoms, bonds, and
  // surfaces occlude volume lobes behind them.
  glBindFramebuffer(GL_READ_FRAMEBUFFER, static_cast<GLuint>(activeFBO));
  const DepthAttachmentFormat currentFormat =
    detectDepthFormat(static_cast<GLuint>(activeFBO));
  if (vpW != m_width || vpH != m_height || currentFormat != d->depthFormat ||
      !d->depthCopyReady) {
    d->depthFormat = currentFormat;
    resizeFBO(vpW, vpH);
  }

  bool hasSceneDepth = false;
  if (d->depthCopyReady) {
    glBindFramebuffer(GL_READ_FRAMEBUFFER, static_cast<GLuint>(activeFBO));
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, d->depthCopyFBO);
    // Drain pre-existing errors so we only test the blit itself.
    for (int i = 0; i < 8 && glGetError() != GL_NO_ERROR; ++i) {}
    glBlitFramebuffer(vpX, vpY, vpX + vpW, vpY + vpH, 0, 0, vpW, vpH,
                      GL_DEPTH_BUFFER_BIT, GL_NEAREST);
    hasSceneDepth = (glGetError() == GL_NO_ERROR);
  }
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, static_cast<GLuint>(activeFBO));
  glBindFramebuffer(GL_READ_FRAMEBUFFER, static_cast<GLuint>(previousReadFBO));

  // Ray marching handles occlusion internally via uSceneDepthTex; disable
  // depth test/write so the fullscreen triangle always runs without altering
  // the depth buffer.
  const bool depthTestWasEnabled = (glIsEnabled(GL_DEPTH_TEST) == GL_TRUE);
  glDisable(GL_DEPTH_TEST);
  glDepthMask(GL_FALSE);

  BlendStateGuard blendState;
  glEnable(GL_BLEND);
  glBlendFuncSeparate(GL_ONE, GL_ONE_MINUS_SRC_ALPHA, GL_ONE,
                      GL_ONE_MINUS_SRC_ALPHA);

  if (d->program->bind()) {
    glActiveTexture(GL_TEXTURE0 + TextureUnitVolume);
    glBindTexture(GL_TEXTURE_3D, d->volumeTexture);
    d->program->setUniformValue("uVolumeData", TextureUnitVolume);

    glActiveTexture(GL_TEXTURE0 + TextureUnitSceneDepth);
    glBindTexture(GL_TEXTURE_2D, hasSceneDepth ? d->depthCopyTexture : 0);
    d->program->setUniformValue("uSceneDepthTex", TextureUnitSceneDepth);
    d->program->setUniformValue("uHasSceneDepth", hasSceneDepth ? 1 : 0);

    const Eigen::Vector3f posCol(m_positiveColor[0] / 255.0f,
                                 m_positiveColor[1] / 255.0f,
                                 m_positiveColor[2] / 255.0f);
    const Eigen::Vector3f negCol(m_negativeColor[0] / 255.0f,
                                 m_negativeColor[1] / 255.0f,
                                 m_negativeColor[2] / 255.0f);
    d->program->setUniformValue("numSteps", 150);
    d->program->setUniformValue("alphaScale", m_alphaScale);
    d->program->setUniformValue("positiveColor", posCol);
    d->program->setUniformValue("negativeColor", negCol);
    d->program->setUniformValue("uInvViewProj", invViewProj);
    d->program->setUniformValue("uBoxInverse", boxInverse);
    d->program->setUniformValue("uBoxDiagonal", boxDiagonal);

    glBindVertexArray(d->vao);
    glDrawArrays(GL_TRIANGLES, 0, 3);
    glBindVertexArray(0);

    glActiveTexture(GL_TEXTURE0);
    d->program->release();
  }

  glDepthMask(GL_TRUE);
  if (depthTestWasEnabled)
    glEnable(GL_DEPTH_TEST);
}

void VolumeGeometry::end()
{
  if (d->vao != 0) {
    glDeleteVertexArrays(1, &d->vao);
    d->vao = 0;
  }
  if (d->volumeTexture != 0) {
    glDeleteTextures(1, &d->volumeTexture);
    d->volumeTexture = 0;
  }
  if (d->depthCopyFBO != 0) {
    glDeleteFramebuffers(1, &d->depthCopyFBO);
    d->depthCopyFBO = 0;
  }
  if (d->depthCopyTexture != 0) {
    glDeleteTextures(1, &d->depthCopyTexture);
    d->depthCopyTexture = 0;
  }
  d->depthCopyReady = false;

  d->program.reset();
  if (d->vertexShader) {
    d->vertexShader->cleanup();
    d->vertexShader.reset();
  }
  if (d->fragmentShader) {
    d->fragmentShader->cleanup();
    d->fragmentShader.reset();
  }
}

} // End namespace Avogadro::Rendering
