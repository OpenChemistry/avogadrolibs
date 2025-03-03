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
 * @class VolumeGeometry volumegeometry.h <avogadro/rendering/volumegeometry.h>
 * @brief The VolumeGeometry class contains a regularly spaced volumetric data
 * set.
 * @author Perminder
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
   * @brief Render the volume.
   * @param camera The current camera to be used for rendering.
   */
  void render(const Camera& camera) override;

  /**
   * Clear the contents of the node.
   */
  void clear() override;

  // TODO: set a color ramp including both positive and negative values
  // e.g., blue to red for positive to negative values
  void setPositiveColor(const Vector3ub& c) { m_positiveColor = c; }
  Vector3ub positiveColor() const { return m_positiveColor; }
  
  void setNegativeColor(const Vector3ub& c) { m_negativeColor = c; }
  Vector3ub negativeColor() const { return m_negativeColor; }

  // data
  void setCube(const Core::Cube& cube);
  const Core::Cube* cube() const { return m_cube; }

protected:
  float m_boundingVertices[24];
  Vector3ub m_positiveColor;
  Vector3ub m_negativeColor;
  const Core::Cube* m_cube = nullptr;

  bool m_dirty = false;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_VOLUMEGEOMETRY_H
