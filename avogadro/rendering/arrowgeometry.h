/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_ARROWGEOMETRY_H
#define AVOGADRO_RENDERING_ARROWGEOMETRY_H

#include "drawable.h"

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>
#include <vector>
#include <utility>

namespace Avogadro {
namespace Rendering {

/**
 * @class ArrowGeometry arrowgeometry.h
 * <avogadro/rendering/arrowgeometry.h>
 * @brief The ArrowGeometry class is used to store sets of cylinders and cones
 * representing arrows.
 */

class AVOGADRORENDERING_EXPORT ArrowGeometry : public Drawable
{
public:
  static const size_t InvalidIndex;

  ArrowGeometry();
  ArrowGeometry(const ArrowGeometry& other);
  ~ArrowGeometry() override;

  ArrowGeometry& operator=(ArrowGeometry);
  friend void swap(ArrowGeometry& lhs, ArrowGeometry& rhs);

  /**
   * Accept a visit from our friendly visitor.
   */
  void accept(Visitor&) override;

  /**
   * @brief Render the arrows.
   * @param camera The current camera to be used for rendering.
   */
  void render(const Camera& camera) override;

  /**
   * Clear the contents of the node.
   */
  void clear() override;

  /**
   * Add a single arrow object.
   * @param pos1 The start coordinate of the arrow.
   * @param pos2 The end coordinate of the arrow.
   * @{
   */
  void addSingleArrow(const Vector3f& pos1, const Vector3f& pos2);
  /** @} */

  void setCylinderRadius(float radius)
  {
    m_cylinderRadius = radius;
    m_geometryDirty = true;
  }
  void setConeRadius(float radius)
  {
    m_coneRadius = radius;
    m_geometryDirty = true;
  }
  void setConeFraction(float fraction)
  {
    m_coneFraction = std::clamp(fraction, 0.0f, 1.0f);
  }

  float cylinderRadius() const { return m_cylinderRadius; }
  float coneRadius() const { return m_coneRadius; }
  float coneFraction() const { return m_coneFraction; }

  /** Set the color of the arrow */
  void setColor(const Vector3ub& c) { m_color = c; }
  const Vector3ub& color() const { return m_color; }

private:
  /**
   * @brief Update the shaders ready for rendering.
   */
  void update();

  void updateGeometry();
  void generateCylinderGeometry(std::vector<float>& vertices,
                                std::vector<unsigned int>& indices,
                                int segments = 16);
  void generateConeGeometry(std::vector<float>& vertices,
                            std::vector<unsigned int>& indices,
                            int segments = 16);

  Core::Array<std::pair<Vector3f, Vector3f>> m_vertices;
  Core::Array<unsigned int> m_lineStarts;
  Vector3ub m_color;

  bool m_dirty;
  bool m_geometryDirty;

  // OpenGL buffers
  unsigned int m_cylinderVAO, m_cylinderVBO, m_cylinderEBO;
  unsigned int m_coneVAO, m_coneVBO, m_coneEBO;
  unsigned int m_cylinderIndexCount;
  unsigned int m_coneIndexCount;

  // Customization parameters
  float m_cylinderRadius;
  float m_coneRadius;
  float m_coneFraction;

  class Private;
  Private* d;
};

inline ArrowGeometry& ArrowGeometry::operator=(ArrowGeometry other)
{
  using std::swap;
  swap(*this, other);
  return *this;
}

inline void swap(ArrowGeometry& lhs, ArrowGeometry& rhs)
{
  using std::swap;
  swap(static_cast<Drawable&>(lhs), static_cast<Drawable&>(rhs));
  swap(lhs.m_vertices, rhs.m_vertices);
  lhs.m_dirty = rhs.m_dirty = true;
}

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_ARROWGEOMETRY_H
