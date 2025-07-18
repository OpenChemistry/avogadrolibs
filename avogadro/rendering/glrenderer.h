/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_GLRENDERER_H
#define AVOGADRO_RENDERING_GLRENDERER_H

#include "avogadrorenderingexport.h"

#include "bufferobject.h"
#include "camera.h"
#include "primitive.h"
#include "scene.h"
#include "shader.h"
#include "shaderprogram.h"
#include "solidpipeline.h"

#include <avogadro/core/array.h>

#include <map>
#include <string> // For member variables.
#include <vector>

namespace Avogadro {
namespace Rendering {
class GeometryNode;
class TextRenderStrategy;

/**
 * @class GLRenderer glrenderer.h <avogadro/rendering/glrenderer.h>
 * @brief Render the scene using OpenGL calls.
 * @author Marcus D. Hanwell
 */

class AVOGADRORENDERING_EXPORT GLRenderer
{
public:
  GLRenderer();
  ~GLRenderer();

  /** Initialize the OpenGL context for rendering. */
  void initialize();

  /** Resize the context in response to window management events. */
  void resize(int width, int height);

  /** Set the ratio of physical to logical pixels. */
  void setPixelRatio(float ratio);

  /** Take care of rendering the scene, requires that the context is current. */
  void render();

  /** Reset the view to fit the entire scene. */
  void resetCamera();

  /**
   * Reset the scene geometry, this should be done when the scene geometry has
   * changed in order to ensure correct clipping.
   */
  void resetGeometry();

  /** Return the primitives under the display coordinate (x,y), mapped by depth.
   */
  std::multimap<float, Identifier> hits(int x, int y) const;

  /** Return the top primitive under the display coordinate (x,y).
   */
  Identifier hit(int x, int y) const;

  /** Return the depth of provided ray - geometry hit test.
   */
  float hit(const Vector3f& rayOrigin, const Vector3f& rayEnd,
            const Vector3f& rayDirection) const;

  /** Return the primitives in the rectangular area provided. */
  Core::Array<Identifier> hits(int x1, int y1, int x2, int y2) const;

  /** Check whether the GL context is valid and supports required features.
   * \sa error() to get more information if the context is not valid.
   */
  bool isValid() const { return m_valid; }

  /** Get the error message if the context is not valid. Empty if valid. */
  std::string error() const { return m_error; }

  /** Get the camera for this renderer. */
  const Camera& camera() const;
  Camera& camera();

  /** Get the overlay camera. */
  const Camera& overlayCamera() const;
  Camera& overlayCamera();

  /** Get the scene for this renderer. */
  const Scene& scene() const { return m_scene; }
  Scene& scene() { return m_scene; }

  /** Get the solid pipeline for this renderer. */
  const SolidPipeline& solidPipeline() const { return m_solidPipeline; }
  SolidPipeline& solidPipeline() { return m_solidPipeline; }

  /**
   * Get/set the text rendering strategy for this object. The renderer takes
   * ownership of the strategy object. @{
   */
  const TextRenderStrategy* textRenderStrategy() const;
  TextRenderStrategy* textRenderStrategy();
  void setTextRenderStrategy(TextRenderStrategy* tren);
  /** @} */

  std::array<float, 6> m_perspectiveFrustum;  // L, R, B, T, N, F (planes order)
  std::array<float, 6> m_orthographicFrustum; // L, R, B, T, N, F (planes order)
#ifdef _3DCONNEXION
  bool m_drawIcon;
  void* m_iconData;
  uint32_t m_iconWidth;
  uint32_t m_iconHeight;
  Eigen::Vector3f m_iconPosition;
#endif

private:
  /**
   * Apply the projection matrix.
   */
  void applyProjection();

  /**
   * @brief Detect hits in a group node.
   */
  std::multimap<float, Identifier> hits(const GroupNode* group,
                                        const Vector3f& rayOrigin,
                                        const Vector3f& rayEnd,
                                        const Vector3f& rayDirection) const;

  /**
   * @brief Detect hits in a geometry node.
   */
  std::multimap<float, Identifier> hits(const GeometryNode* geometry,
                                        const Vector3f& rayOrigin,
                                        const Vector3f& rayEnd,
                                        const Vector3f& rayDirection) const;

  Core::Array<Identifier> hits(const GroupNode* group,
                               const Frustrum& frustrum) const;

  bool m_valid;
  std::string m_error;
  Camera m_camera;
  Camera m_overlayCamera;
  Scene m_scene;
  TextRenderStrategy* m_textRenderStrategy;
  SolidPipeline m_solidPipeline;

  Vector3f m_center;
  float m_radius;
};

inline const Camera& GLRenderer::camera() const
{
  return m_camera;
}

inline Camera& GLRenderer::camera()
{
  return m_camera;
}

inline const Camera& GLRenderer::overlayCamera() const
{
  return m_camera;
}

inline Camera& GLRenderer::overlayCamera()
{
  return m_camera;
}

inline const TextRenderStrategy* GLRenderer::textRenderStrategy() const
{
  return m_textRenderStrategy;
}

inline TextRenderStrategy* GLRenderer::textRenderStrategy()
{
  return m_textRenderStrategy;
}

inline Identifier GLRenderer::hit(int x, int y) const
{
  std::multimap<float, Identifier> results = hits(x, y);
  if (results.size())
    return results.begin()->second;
  return Identifier();
}

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_GLRENDERER_H
