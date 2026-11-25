/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_VOLUMEGEOMETRY_H
#define AVOGADRO_RENDERING_VOLUMEGEOMETRY_H

#include "drawable.h"
#include <avogadro/core/cube.h>

namespace Avogadro::Rendering {

/**
 * @class VolumeGeometry
 * @brief Single-pass volume rendering by ray marching a 3D texture of the
 * cube data in a fullscreen fragment shader.
 */
class AVOGADRORENDERING_EXPORT VolumeGeometry : public Drawable
{
public:
  VolumeGeometry();
  VolumeGeometry(const VolumeGeometry& other);
  ~VolumeGeometry() override;

  VolumeGeometry& operator=(VolumeGeometry);
  friend void swap(VolumeGeometry& lhs, VolumeGeometry& rhs);

  /**
   * Accept a visit from our friendly visitor.
   */
  void accept(Visitor&) override;

  /**
   * Render the volume.
   */
  void render(const Camera& camera) override;

  /**
   * Destroy all GL resources (volume texture, scene depth copy, shaders).
   */
  void end();

  /**
   * Clear the contents of the node.
   */
  void clear() override;

  /**
   * Call once to initialize all GL objects/shaders.
   */
  void initialize();

  /**
   * Resize the copy of the scene depth buffer that stops rays at opaque
   * geometry (atoms, bonds, surfaces).
   */
  void resizeFBO(int width, int height);

  /**
   * Colors for positive/negative isovalues (for real volume rendering).
   */
  void setPositiveColor(const Vector3ub& c) { m_positiveColor = c; }
  Vector3ub positiveColor() const { return m_positiveColor; }

  void setNegativeColor(const Vector3ub& c) { m_negativeColor = c; }
  Vector3ub negativeColor() const { return m_negativeColor; }

  /**
   * Scale applied to the per-sample opacity of the ray march (intensity of
   * the volume). Defaults to 1.0. Negative values are clamped to 0; NaN is
   * ignored.
   */
  void setAlphaScale(float scale);
  float alphaScale() const { return m_alphaScale; }

  /**
   * Assign which Cube to render.
   */
  void setCube(const Core::Cube& cube);
  const Core::Cube* cube() const { return m_cube; }

protected:
  Vector3ub m_positiveColor;
  Vector3ub m_negativeColor;
  const Core::Cube* m_cube = nullptr;
  float m_alphaScale = 1.0f;
  bool m_dirty = false;

  class Private;
  Private* d;

  // Viewport size of the scene depth copy:
  int m_width;
  int m_height;
};

} // namespace Avogadro::Rendering
// End namespace Avogadro

#endif // AVOGADRO_RENDERING_VOLUMEGEOMETRY_H
