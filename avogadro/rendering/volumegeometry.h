/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_VOLUMEGEOMETRY_H
#define AVOGADRO_RENDERING_VOLUMEGEOMETRY_H

#include "drawable.h"
#include <avogadro/core/cube.h>

namespace Avogadro {
namespace Rendering {

/**
 * @class VolumeGeometry
 * @brief Demonstrates volume rendering with an offscreen pass and a fullscreen quad.
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
   * Destroy all GL resources (FBO, textures, etc.).
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
  void resizeFBO(int width, int height);

  /**
   * Colors for positive/negative isovalues (for real volume rendering).
   */
  void setPositiveColor(const Vector3ub& c) { m_positiveColor = c; }
  Vector3ub positiveColor() const { return m_positiveColor; }

  void setNegativeColor(const Vector3ub& c) { m_negativeColor = c; }
  Vector3ub negativeColor() const { return m_negativeColor; }

  /**
   * Assign which Cube to render.
   */
  void setCube(const Core::Cube& cube);
  const Core::Cube* cube() const { return m_cube; }

protected:
  // We store bounding box vertices, for real volume rendering if needed:
  float m_boundingVertices[24];
  Vector3ub m_positiveColor;
  Vector3ub m_negativeColor;
  const Core::Cube* m_cube = nullptr;
  bool m_dirty = false;

  class Private;
  Private* d;

  // Size at which we create our offscreen buffer:
  int m_width;
  int m_height;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_VOLUMEGEOMETRY_H
