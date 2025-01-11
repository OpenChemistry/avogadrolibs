/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_ARROWGEOMETRY_H
#define AVOGADRO_RENDERING_ARROWGEOMETRY_H

#include "drawable.h"

#include <avogadro/core/array.h>

namespace Avogadro {
namespace Rendering {

/**
 * @class ArrowGeometry arrowgeometry.h
 * <avogadro/rendering/arrowgeometry.h>
 * @brief The ArrowGeometry class is used to store sets of line strips.
 */

class AVOGADRORENDERING_EXPORT ArrowGeometry : public Drawable
{
public:
  static const size_t InvalidIndex;

  ArrowGeometry();
  ArrowGeometry(const ArrowGeometry& other);
  ~ArrowGeometry();

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

  void drawLine(const Vector3f& start, const Vector3f& end, double lineWidth);
  void drawCone(const Vector3f& base, const Vector3f& cap, double baseRadius,
                double);

  /**
   * Add a single arrow object.
   * @param pos1 The start coordinate of the arrow.
   * @param pos2 The end coordinate of the arrow.
   * @{
   */
  void addSingleArrow(const Vector3f& pos1, const Vector3f& pos2);
  /** @} */

  /** The vertex array. */
  Core::Array<std::pair<Vector3f, Vector3f>> vertices() const
  {
    return m_vertices;
  }

  /** Set the color of the arrow */
  void setColor(const Vector3ub& c) { m_color = c; }

private:
  /**
   * @brief Update the shaders ready for rendering.
   */
  void update();

  Core::Array<std::pair<Vector3f, Vector3f>> m_vertices;
  Core::Array<unsigned int> m_lineStarts;
  Vector3ub m_color;

  bool m_dirty;

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
