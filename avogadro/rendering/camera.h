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

#ifndef AVOGADRO_RENDERING_CAMERA_H
#define AVOGADRO_RENDERING_CAMERA_H

#include "avogadrorenderingexport.h"

#include <avogadro/core/vector.h> // For vector types.

#include <Eigen/Geometry> // For member variables.
#include <memory>

namespace Avogadro {
namespace Rendering {

enum Projection
{
  Perspective,
  Orthographic
};

// Separate Eigen datastructures to ensure sufficient memory alignment.
struct EigenData
{
  EIGEN_MAKE_ALIGNED_OPERATOR_NEW
  Eigen::Affine3f projection;
  Eigen::Affine3f modelView;
};

/**
 * @class Camera camera.h <avogadro/rendering/camera.h>
 * @brief The Camera class provides utility functionality useful in camera's
 * used with 3D scenes.
 * @author Marcus D. Hanwell
 */

class AVOGADRORENDERING_EXPORT Camera
{
public:
  Camera();
  Camera(const Camera& o);
  Camera& operator=(const Camera& o);
  ~Camera();

  /**
   * Translate the camera's model view matrix using the supplied translation
   * vector @p translate.
   */
  void translate(const Vector3f& translate);

  /**
   * Pretranslate the camera's model view matrix using the supplied translation
   * vector @p translate.
   */
  void preTranslate(const Vector3f& translate);

  /**
   * Rotate the camera about the supplied @p axis by @p angle (degrees).
   */
  void rotate(float angle, const Vector3f& axis);

  /**
   * Prerotate the camera about the supplied @p axis by @p angle (degrees).
   */
  void preRotate(float angle, const Vector3f& axis);

  /**
   * Modify the matrix, to give the effect of zooming in or out.
   */
  void scale(float scale);

  /**
   * Set the model-view matrix to the "look at" transformation matrix.
   * @param eye the position of the eye/camera.
   * @param center the position to look at.
   * @param up the vector pointing up.
   */
  void lookAt(const Vector3f& eye, const Vector3f& center, const Vector3f& up);

  /**
   * Distance to supplied point @p point and the camera.
   */
  float distance(const Vector3f& point) const;

  /**
   * Projects a point from the scene to the window.
   */
  Vector3f project(const Vector3f& point) const;

  /**
   * Unprojects a point from the window to the scene.
   */
  Vector3f unProject(const Vector3f& point) const;

  /**
   * Unprojects a point from the window to the scene, using the supplied
   * reference point (defaults to the origin if nothing is supplied).
   */
  Vector3f unProject(const Vector2f& point,
                     const Vector3f& reference = Vector3f::Zero()) const;

  /**
   * Calculate the perspective projection matrix.
   * @param fieldOfView angle in degrees in the y direction.
   * @param aspectRatio is the ratio of width to height.
   * @param zNear is the distance from the viewer to the near clipping plane.
   * @param zFar is the distance from the viewer to the far clipping plane.
   */
  void calculatePerspective(float fieldOfView, float aspectRatio, float zNear,
                            float zFar);

  /**
   * Calculate the perspective projection matrix. Computes the aspect ratio
   * from the width and height stored by the Camera object.
   * @param fieldOfView angle in degrees in the y direction.
   * @param zNear is the distance from the viewer to the near clipping plane.
   * @param zFar is the distance from the viewer to the far clipping plane.
   */
  void calculatePerspective(float fieldOfView, float zNear, float zFar);

  /**
   * Calculate the orthographic projection matrix.
   * @param left left vertical clipping plane.
   * @param right right vertical clipping plane.
   * @param bottom bottom horizontal clipping plane.
   * @param top top horizontal clipping plane.
   * @param zNear distance to the near clipping plane.
   * @param zFar distance to the far clipping plane.
   */
  void calculateOrthographic(float left, float right, float bottom, float top,
                             float zNear, float zFar);

  /**
   * Set the dimensions of the viewport in pixels.
   */
  void setViewport(int w, int h);

  /**
   * Get the width of the viewport in pixels.
   */
  int width() const { return m_width; }

  /**
   * Get the height of the viewport in pixels.
   */
  int height() const { return m_height; }

  /**
   * Set the model view matrix to the identity. This resets the model view
   * matrix.
   */
  void setIdentity() { m_data->modelView.setIdentity(); }

  /**
   * Set the projection transform.
   */
  void setProjection(const Eigen::Affine3f& transform);

  /**
   * Get a reference to the projection matrix.
   */
  const Eigen::Affine3f& projection() const;

  /**
   * Set the model view transform.
   */
  void setModelView(const Eigen::Affine3f& transform);

  /** Get a reference to the model view matrix. */
  const Eigen::Affine3f& modelView() const;

  /**
   * Set the projection type for this camera (Perspective or Orthographic).
   * @param proj The projection type to use.
   */
  void setProjectionType(Projection proj) { m_projectionType = proj; }

  /**
   * Get the projection type the camera is using.
   * @return The current projection type.
   */
  Projection projectionType() const { return m_projectionType; }

  /**
   * Set the orthographic scale, this defaults to 1.0. Affects calculation of
   * the orthographic projection matrix.
   * @param newScale The factor to scale orthographic projection by.
   */
  void setOrthographicScale(float newScale) { m_orthographicScale = newScale; }

  /**
   * Get the value of the orthographic scale, defaults to 1.0.
   * @return The current value of the orthographic scale.
   */
  float orthographicScale() const { return m_orthographicScale; }

private:
  int m_width;
  int m_height;
  Projection m_projectionType;
  float m_orthographicScale;
  std::unique_ptr<EigenData> m_data;
};

inline const Eigen::Affine3f& Camera::projection() const
{
  return m_data->projection;
}

inline const Eigen::Affine3f& Camera::modelView() const
{
  return m_data->modelView;
}

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_CAMERA_H
