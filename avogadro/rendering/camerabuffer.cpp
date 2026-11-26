/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "camerabuffer_p.h"

#include "avogadrogl.h"
#include "camera.h"

#include <cmath>
#include <cstring>

namespace Avogadro::Rendering {

namespace {

// Keep this in step with CameraBlock: std140 places each member at the offset
// the static_asserts in the header check.
const char* const CameraBlockSource = "layout(std140) uniform CameraBuffer {\n"
                                      "  mat4 modelView;\n"
                                      "  mat4 projection;\n"
                                      "  mat4 inverseProjection;\n"
                                      "  mat4 normalMatrix;\n"
                                      "  vec4 viewport;\n"
                                      "  vec4 cameraParams;\n"
                                      "  vec4 sceneBounds;\n"
                                      "};\n";

// Eigen and GLSL are both column-major.
void copyMatrix(float* destination, const Matrix4f& matrix)
{
  std::memcpy(destination, matrix.data(), 16 * sizeof(float));
}

float finiteOrZero(float value)
{
  return std::isfinite(value) ? value : 0.0f;
}

// 1 / value, or 0 when that is not a finite number.
float safeInverse(float value)
{
  return value != 0.0f && std::isfinite(value) ? 1.0f / value : 0.0f;
}

} // namespace

const char* cameraBlockGlsl()
{
  return CameraBlockSource;
}

std::string insertCameraBlock(const std::string& source)
{
  std::string result = source;
  std::size_t position = 0;
  const std::size_t version = result.find("#version");
  if (version != std::string::npos) {
    const std::size_t lineEnd = result.find('\n', version);
    if (lineEnd == std::string::npos)
      result += '\n';
    position = lineEnd == std::string::npos ? result.size() : lineEnd + 1;
  }
  result.insert(position, CameraBlockSource);
  return result;
}

CameraBlockState::CameraBlockState()
{
  std::memset(&m_block, 0, sizeof(m_block));
  m_modelView.setZero();
  m_projection.setZero();
}

void CameraBlockState::setFrameParameters(float pixelRatio,
                                          const Vector3f& sceneCenter,
                                          float sceneRadius)
{
  if (!(pixelRatio > 0.0f) || !std::isfinite(pixelRatio))
    pixelRatio = 1.0f;
  Vector3f center = sceneCenter;
  if (!center.allFinite())
    center.setZero();
  if (!(sceneRadius >= 0.0f) || !std::isfinite(sceneRadius))
    sceneRadius = 0.0f;
  if (pixelRatio == m_pixelRatio && center == m_sceneCenter &&
      sceneRadius == m_sceneRadius) {
    return;
  }
  m_pixelRatio = pixelRatio;
  m_sceneCenter = center;
  m_sceneRadius = sceneRadius;
  m_valid = false;
}

bool CameraBlockState::update(const Camera& camera)
{
  const Matrix4f& modelView = camera.modelView().matrix();
  const Matrix4f& projection = camera.projection().matrix();
  if (m_valid && camera.width() == m_width && camera.height() == m_height &&
      modelView == m_modelView && projection == m_projection) {
    return false;
  }
  m_block = build(camera, m_pixelRatio, m_sceneCenter, m_sceneRadius);
  m_modelView = modelView;
  m_projection = projection;
  m_width = camera.width();
  m_height = camera.height();
  m_valid = true;
  return true;
}

CameraBlock CameraBlockState::build(const Camera& camera, float pixelRatio,
                                    const Vector3f& sceneCenter,
                                    float sceneRadius)
{
  CameraBlock block;
  std::memset(&block, 0, sizeof(block));

  const Matrix4f modelView = camera.modelView().matrix();
  const Matrix4f projection = camera.projection().matrix();
  copyMatrix(block.modelView, modelView);
  copyMatrix(block.projection, projection);

  // A singular projection has no inverse: leave zeros rather than infinity.
  const Matrix4f inverseProjection = projection.inverse();
  if (inverseProjection.allFinite())
    copyMatrix(block.inverseProjection, inverseProjection);

  // The same expression the drawables used to evaluate for themselves.
  const Matrix3f normalMatrix =
    camera.modelView().linear().inverse().transpose();
  Matrix4f normal = Matrix4f::Zero();
  if (normalMatrix.allFinite())
    normal.topLeftCorner<3, 3>() = normalMatrix;
  normal(3, 3) = 1.0f;
  copyMatrix(block.normalMatrix, normal);

  // The camera works in logical pixels; the viewport is in device pixels.
  const float width = static_cast<float>(camera.width()) * pixelRatio;
  const float height = static_cast<float>(camera.height()) * pixelRatio;
  block.viewport[0] = finiteOrZero(width);
  block.viewport[1] = finiteOrZero(height);
  block.viewport[2] = safeInverse(width);
  block.viewport[3] = safeInverse(height);

  block.cameraParams[0] = pixelRatio;
  block.cameraParams[1] = finiteOrZero(camera.nearPlane());
  block.cameraParams[2] = finiteOrZero(camera.farPlane());
  block.cameraParams[3] = camera.isOrthographic() ? 1.0f : 0.0f;

  block.sceneBounds[0] = sceneCenter.x();
  block.sceneBounds[1] = sceneCenter.y();
  block.sceneBounds[2] = sceneCenter.z();
  block.sceneBounds[3] = sceneRadius;
  return block;
}

CameraBuffer::~CameraBuffer()
{
  release();
}

bool CameraBuffer::use(const Camera& camera)
{
  if (m_handle == 0) {
    GLuint handle = 0;
    glGenBuffers(1, &handle);
    if (handle == 0)
      return false;
    m_handle = handle;
    glBindBufferBase(GL_UNIFORM_BUFFER, CameraBufferBindingPoint, m_handle);
    glBufferData(GL_UNIFORM_BUFFER, sizeof(CameraBlock), nullptr,
                 GL_DYNAMIC_DRAW);
    m_state.invalidate(); // The new storage holds nothing yet.
  } else {
    // Something else in the context may have changed the binding point.
    glBindBufferBase(GL_UNIFORM_BUFFER, CameraBufferBindingPoint, m_handle);
  }
  if (m_state.update(camera)) {
    glBufferSubData(GL_UNIFORM_BUFFER, 0, sizeof(CameraBlock),
                    &m_state.block());
  }
  return true;
}

void CameraBuffer::release()
{
  if (m_handle != 0) {
    const GLuint handle = m_handle;
    glDeleteBuffers(1, &handle);
  }
  abandon();
}

void CameraBuffer::abandon()
{
  m_handle = 0;
  m_state.invalidate();
}

} // namespace Avogadro::Rendering
