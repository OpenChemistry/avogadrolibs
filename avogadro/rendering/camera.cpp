/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "camera.h"

#include <Eigen/LU>

#include <cmath>

namespace Avogadro::Rendering {

Camera::Camera()
  : m_width(0), m_height(0), m_projectionType(Perspective),
    m_orthographicScale(1.0), m_data(new EigenData), m_focus(NAN, NAN, NAN)
{
  m_data->projection.setIdentity();
  m_data->modelView.setIdentity();
}

Camera::Camera(const Camera& o)
  : m_width(o.m_width), m_height(o.m_height),
    m_projectionType(o.m_projectionType),
    m_orthographicScale(o.m_orthographicScale), m_data(new EigenData(*o.m_data))
{
}

Camera& Camera::operator=(const Camera& o)
{
  if (this != &o) {
    m_width = o.m_width;
    m_height = o.m_height;
    m_projectionType = o.m_projectionType;
    m_orthographicScale = o.m_orthographicScale;
    m_data = std::unique_ptr<EigenData>(new EigenData(*o.m_data));
  }

  return *this;
}

Camera::~Camera() {}

void Camera::translate(const Vector3f& translate_)
{
  m_data->modelView.translate(translate_);
}

void Camera::preTranslate(const Vector3f& translate_)
{
  m_data->modelView.pretranslate(translate_);
}

void Camera::rotate(float angle, const Vector3f& axis)
{
  m_data->modelView.rotate(Eigen::AngleAxisf(angle, axis));
}

void Camera::preRotate(float angle, const Vector3f& axis)
{
  m_data->modelView.prerotate(Eigen::AngleAxisf(angle, axis));
}

void Camera::scale(float s)
{
  if (m_projectionType == Perspective)
    m_data->modelView.scale(s);
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

  m_data->modelView.setIdentity();
  m_data->modelView(0, 0) = s.x();
  m_data->modelView(0, 1) = s.y();
  m_data->modelView(0, 2) = s.z();
  m_data->modelView(1, 0) = u.x();
  m_data->modelView(1, 1) = u.y();
  m_data->modelView(1, 2) = u.z();
  m_data->modelView(2, 0) = -f.x();
  m_data->modelView(2, 1) = -f.y();
  m_data->modelView(2, 2) = -f.z();
  m_data->modelView(0, 3) = -s.dot(eye);
  m_data->modelView(1, 3) = -u.dot(eye);
  m_data->modelView(2, 3) = f.dot(eye);
}

float Camera::distance(const Vector3f& point) const
{
  return (m_data->modelView * point).norm();
}

Vector3f Camera::project(const Vector3f& point) const
{
  Eigen::Matrix4f mvp =
    m_data->projection.matrix() * m_data->modelView.matrix();
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
  Eigen::Matrix4f mvp =
    m_data->projection.matrix() * m_data->modelView.matrix();
  Vector4f result(2.0f * point.x() / static_cast<float>(m_width) - 1.0f,
                  2.0f * (static_cast<float>(m_height) - point.y()) /
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
  m_data->projection.setIdentity();
  float f = 1.0f / std::tan(fieldOfView * float(M_PI) / 360.0f);
  m_data->projection(0, 0) = f / aspectRatio;
  m_data->projection(1, 1) = f;
  m_data->projection(2, 2) = (zNear + zFar) / (zNear - zFar);
  m_data->projection(2, 3) = (2.0f * zFar * zNear) / (zNear - zFar);
  m_data->projection(3, 2) = -1;
  m_data->projection(3, 3) = 0;
}

void Camera::calculatePerspective(float fieldOfView, float zNear, float zFar)
{
  calculatePerspective(
    fieldOfView, static_cast<float>(m_width) / static_cast<float>(m_height),
    zNear, zFar);
}

void Camera::calculateOrthographic(float left, float right, float bottom,
                                   float top, float zNear, float zFar)
{
  left *= m_orthographicScale;
  right *= m_orthographicScale;
  bottom *= m_orthographicScale;
  top *= m_orthographicScale;
  m_data->projection.setIdentity();
  m_data->projection(0, 0) = 2.0f / (right - left);
  m_data->projection(0, 3) = -(right + left) / (right - left);
  m_data->projection(1, 1) = 2.0f / (top - bottom);
  m_data->projection(1, 3) = -(top + bottom) / (top - bottom);
  m_data->projection(2, 2) = -2.0f / (zFar - zNear);
  m_data->projection(2, 3) = -(zFar + zNear) / (zFar - zNear);
  m_data->projection(3, 3) = 1;
}

void Camera::setViewport(int w, int h)
{
  m_width = w;
  m_height = h;
}

void Camera::setProjection(const Eigen::Affine3f& transform)
{
  m_data->projection = transform;
}

void Camera::setModelView(const Eigen::Affine3f& transform)
{
  m_data->modelView = transform;
}

bool Camera::isOrthographic() const
{
  // A projection is only defined up to a homogeneous scale: k * P is the same
  // projection. Orthographic has w = 1 (P(3, 3) != 0, P(3, 2) == 0),
  // perspective has w = -z (P(3, 3) == 0, P(3, 2) != 0).
  const Eigen::Matrix4f& p = m_data->projection.matrix();
  return p(3, 3) != 0.0f && p(3, 2) == 0.0f;
}

Eigen::Matrix4f Camera::normalizedProjection() const
{
  const Eigen::Matrix4f& p = m_data->projection.matrix();
  const float scale = isOrthographic() ? p(3, 3) : -p(3, 2);
  if (scale == 0.0f)
    return p;
  return p / scale;
}

float Camera::verticalFieldOfView() const
{
  if (isOrthographic())
    return 0.0f;
  const double p11 = normalizedProjection()(1, 1);
  return static_cast<float>(360.0 / M_PI * std::atan(1.0 / std::abs(p11)));
}

float Camera::aspectRatio() const
{
  const Eigen::Matrix4f p = normalizedProjection();
  return std::abs(p(1, 1) / p(0, 0));
}

float Camera::nearPlane() const
{
  const Eigen::Matrix4f p = normalizedProjection();
  const double p22 = p(2, 2);
  const double p23 = p(2, 3);
  return static_cast<float>(isOrthographic() ? (p23 + 1.0) / p22
                                             : p23 / (p22 - 1.0));
}

float Camera::farPlane() const
{
  const Eigen::Matrix4f p = normalizedProjection();
  const double p22 = p(2, 2);
  const double p23 = p(2, 3);
  return static_cast<float>(isOrthographic() ? (p23 - 1.0) / p22
                                             : p23 / (p22 + 1.0));
}

Vector2f Camera::orthographicHalfExtents() const
{
  if (!isOrthographic())
    return Vector2f::Zero();
  const Eigen::Matrix4f p = normalizedProjection();
  return Vector2f(1.0f / std::abs(p(0, 0)), 1.0f / std::abs(p(1, 1)));
}

Vector2f Camera::orthographicCenter() const
{
  if (!isOrthographic())
    return Vector2f::Zero();
  const Eigen::Matrix4f p = normalizedProjection();
  return Vector2f(-p(0, 3) / p(0, 0), -p(1, 3) / p(1, 1));
}

float Camera::viewScale() const
{
  return m_data->modelView.matrix().topLeftCorner<3, 1>().norm();
}

Eigen::Matrix3f Camera::viewRotation() const
{
  const Eigen::Matrix3f linear =
    m_data->modelView.matrix().topLeftCorner<3, 3>();
  return (linear / viewScale()).transpose();
}

Vector3f Camera::eyePosition() const
{
  const Eigen::Matrix4f& m = m_data->modelView.matrix();
  const Eigen::Matrix3d linear = m.topLeftCorner<3, 3>().cast<double>();
  const Eigen::Vector3d translation = m.topRightCorner<3, 1>().cast<double>();
  const double s = linear.col(0).norm();
  return (-(linear.transpose() * translation) / (s * s)).cast<float>();
}

void Camera::calculatePerspective(float left, float right, float bottom,
                                  float top, float zNear, float zFar)
{
  m_data->projection.setIdentity();

  m_data->projection(0, 0) = (2.0f * zNear) / (right - left);
  m_data->projection(1, 1) = (2.0f * zNear) / (top - bottom);
  m_data->projection(0, 2) = (right + left) / (right - left);
  m_data->projection(1, 2) = (top + bottom) / (top - bottom);
  m_data->projection(2, 2) = -(zFar + zNear) / (zFar - zNear);
  m_data->projection(3, 2) = -1.0f;
  m_data->projection(2, 3) = -(2.0f * zFar * zNear) / (zFar - zNear);
  m_data->projection(3, 3) = 0.0f;
}

} // namespace Avogadro::Rendering
