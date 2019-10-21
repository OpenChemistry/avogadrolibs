/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-2014 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "camera.h"

#include <Eigen/LU>

#include <cmath>

namespace Avogadro {
namespace Rendering {

Camera::Camera()
  : m_width(0), m_height(0), m_pixelScale(1.0), m_projectionType(Perspective),
    m_orthographicScale(1.0)
{
  m_projection.setIdentity();
  m_modelView.setIdentity();
}

Camera::~Camera()
{
}

void Camera::translate(const Vector3f& translate_)
{
  m_modelView.translate(translate_);
}

void Camera::preTranslate(const Vector3f& translate_)
{
  m_modelView.pretranslate(translate_);
}

void Camera::rotate(float angle, const Vector3f& axis)
{
  m_modelView.rotate(Eigen::AngleAxisf(angle, axis));
}

void Camera::preRotate(float angle, const Vector3f& axis)
{
  m_modelView.prerotate(Eigen::AngleAxisf(angle, axis));
}

void Camera::scale(float s)
{
  if (m_projectionType == Perspective)
    m_modelView.scale(s);
  else
    m_orthographicScale *= s;
}

void Camera::lookAt(const Vector3f& eye, const Vector3f& center,
                    const Vector3f& up)
{
  Vector3f f = (center - eye).normalized();
  Vector3f u = up.normalized();
  Vector3f s = f.cross(u).normalized();
  u = s.cross(f);

  m_modelView.setIdentity();
  m_modelView(0, 0) = s.x();
  m_modelView(0, 1) = s.y();
  m_modelView(0, 2) = s.z();
  m_modelView(1, 0) = u.x();
  m_modelView(1, 1) = u.y();
  m_modelView(1, 2) = u.z();
  m_modelView(2, 0) = -f.x();
  m_modelView(2, 1) = -f.y();
  m_modelView(2, 2) = -f.z();
  m_modelView(0, 3) = -s.dot(eye);
  m_modelView(1, 3) = -u.dot(eye);
  m_modelView(2, 3) = f.dot(eye);
}

float Camera::distance(const Vector3f& point) const
{
  return (m_modelView * point).norm();
}

Vector3f Camera::project(const Vector3f& point) const
{
  Eigen::Matrix4f mvp = m_projection.matrix() * m_modelView.matrix();
  Vector4f tPoint(point.x(), point.y(), point.z(), 1.0f);
  tPoint = mvp * tPoint;
  Vector3f result(
    static_cast<float>(m_width) * (tPoint.x() / tPoint.w() + 1.0f) / 2.0f,
    static_cast<float>(m_height) * (tPoint.y() / tPoint.w() + 1.0f) / 2.0f,
    (tPoint.z() / tPoint.w() + 1.0f) / 2.0f);
  return result;
}

Vector3f Camera::unProject(const Vector3f& point) const
{
  Eigen::Matrix4f mvp = m_projection.matrix() * m_modelView.matrix();
  Vector4f result(
    2.0f * m_pixelScale * point.x() / static_cast<float>(m_width) - 1.0f,
    2.0f * (static_cast<float>(m_height) - m_pixelScale * point.y()) /
        static_cast<float>(m_height) -
      1.0f,
    2.0f * point.z() - 1.0f, 1.0f);
  result = mvp.matrix().inverse() * result;
  return Vector3f(result.x() / result.w(), result.y() / result.w(),
                  result.z() / result.w());
}

Vector3f Camera::unProject(const Vector2f& point,
                           const Vector3f& reference) const
{
  return unProject(Vector3f(point.x(), point.y(), project(reference).z()));
}

void Camera::calculatePerspective(float fieldOfView, float aspectRatio,
                                  float zNear, float zFar)
{
  m_projection.setIdentity();
  float f = 1.0f / std::tan(fieldOfView * float(M_PI) / 360.0f);
  m_projection(0, 0) = f / aspectRatio;
  m_projection(1, 1) = f;
  m_projection(2, 2) = (zNear + zFar) / (zNear - zFar);
  m_projection(2, 3) = (2.0f * zFar * zNear) / (zNear - zFar);
  m_projection(3, 2) = -1;
  m_projection(3, 3) = 0;
}

void Camera::calculatePerspective(float fieldOfView, float zNear, float zFar)
{
  calculatePerspective(fieldOfView, static_cast<float>(m_width) /
                                      static_cast<float>(m_height),
                       zNear, zFar);
}

void Camera::calculateOrthographic(float left, float right, float bottom,
                                   float top, float zNear, float zFar)
{
  left *= m_orthographicScale;
  right *= m_orthographicScale;
  bottom *= m_orthographicScale;
  top *= m_orthographicScale;
  m_projection.setIdentity();
  m_projection(0, 0) = 2.0f / (right - left);
  m_projection(0, 3) = -(right + left) / (right - left);
  m_projection(1, 1) = 2.0f / (top - bottom);
  m_projection(1, 3) = -(top + bottom) / (top - bottom);
  m_projection(2, 2) = -2.0f / (zFar - zNear);
  m_projection(2, 3) = -(zFar + zNear) / (zFar - zNear);
  m_projection(3, 3) = 1;
}

void Camera::setViewport(int w, int h)
{
  m_width = w;
  m_height = h;
}

void Camera::setDevicePixelRatio(float scale)
{
  m_pixelScale = scale;
}

void Camera::setProjection(const Eigen::Affine3f& transform)
{
  m_projection = transform;
}

void Camera::setModelView(const Eigen::Affine3f& transform)
{
  m_modelView = transform;
}

} // End Rendering namespace
} // End Avogadro namespace
