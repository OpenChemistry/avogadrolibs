/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_WIDELINEGEOMETRY_H
#define AVOGADRO_RENDERING_WIDELINEGEOMETRY_H

#include "drawable.h"

#include <vector>

namespace Avogadro {
namespace Rendering {

/**
 * @class WideLineGeometry widelinegeometry.h
 * <avogadro/rendering/widelinegeometry.h>
 * @brief Renders line segments as camera-facing quads for wide line support.
 *
 * OpenGL 4.0 Core Profile does not guarantee glLineWidth() > 1.0. This class
 * renders each line segment as a quad (two triangles) whose width is computed
 * in the vertex shader, producing correct wide lines on all platforms.
 *
 * Width is specified in world-space units.
 */

class AVOGADRORENDERING_EXPORT WideLineGeometry : public Drawable
{
public:
  struct PackedVertex
  {                    // 32 bytes total:
    Vector3f position; // 12 bytes - this endpoint
    Vector3f otherEnd; // 12 bytes - the other endpoint
    Vector4ub color;   //  4 bytes - RGBA
    float widthSide;   //  4 bytes - half-width * side (+1 or -1)

    PackedVertex() = default;
    PackedVertex(const Vector3f& pos, const Vector3f& other, const Vector4ub& c,
                 float ws)
      : position(pos), otherEnd(other), color(c), widthSide(ws)
    {
    }

    static int positionOffset() { return 0; }
    static int otherEndOffset() { return static_cast<int>(sizeof(Vector3f)); }
    static int colorOffset() { return static_cast<int>(2 * sizeof(Vector3f)); }
    static int widthSideOffset()
    {
      return static_cast<int>(2 * sizeof(Vector3f) + sizeof(Vector4ub));
    }
  };

  WideLineGeometry();
  WideLineGeometry(const WideLineGeometry& other);
  ~WideLineGeometry() override;

  WideLineGeometry& operator=(WideLineGeometry);
  friend void swap(WideLineGeometry& lhs, WideLineGeometry& rhs);

  /**
   * Accept a visit from our friendly visitor.
   */
  void accept(Visitor&) override;

  /**
   * @brief Render the wide line geometry.
   * @param camera The current camera to be used for rendering.
   */
  void render(const Camera& camera) override;

  /**
   * Clear the contents of the node.
   */
  void clear() override;

  /**
   * Add a single line segment.
   * @param start Start position of the line segment.
   * @param end End position of the line segment.
   * @param colorStart Color at the start.
   * @param colorEnd Color at the end.
   * @param lineWidth Width of the line in world-space units.
   */
  void addLine(const Vector3f& start, const Vector3f& end,
               const Vector3ub& colorStart, const Vector3ub& colorEnd,
               float lineWidth);

  /**
   * Add a single line segment with a uniform color.
   */
  void addLine(const Vector3f& start, const Vector3f& end,
               const Vector3ub& color, float lineWidth);

  /**
   * The default color of the lines.
   * @{
   */
  void setColor(const Vector3ub& c) { m_color = c; }
  Vector3ub color() const { return m_color; }
  /** @} */

  /**
   * The default opacity of the lines.
   * @{
   */
  void setOpacity(unsigned char opacity_) { m_opacity = opacity_; }
  unsigned char opacity() const { return m_opacity; }
  /** @} */

  /**
   * Reserve space for the given number of line segments.
   * Each segment uses 4 vertices and 6 indices.
   */
  void reserve(size_t lineCount);

  /** The vertex array (for geometry bounds computation). */
  const std::vector<PackedVertex>& vertices() const { return m_vertices; }

  /** The number of line segments. */
  size_t lineCount() const { return m_vertices.size() / 4; }

private:
  /**
   * @brief Update the VBOs, IBOs etc ready for rendering.
   */
  void update();

  std::vector<PackedVertex> m_vertices;
  std::vector<unsigned int> m_indices;

  Vector3ub m_color;
  unsigned char m_opacity;

  bool m_dirty;

  class Private;
  Private* d;
};

inline WideLineGeometry& WideLineGeometry::operator=(WideLineGeometry other)
{
  using std::swap;
  swap(*this, other);
  return *this;
}

inline void swap(WideLineGeometry& lhs, WideLineGeometry& rhs)
{
  using std::swap;
  swap(static_cast<Drawable&>(lhs), static_cast<Drawable&>(rhs));
  swap(lhs.m_vertices, rhs.m_vertices);
  swap(lhs.m_indices, rhs.m_indices);
  swap(lhs.m_color, rhs.m_color);
  swap(lhs.m_opacity, rhs.m_opacity);
  lhs.m_dirty = rhs.m_dirty = true;
}

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_WIDELINEGEOMETRY_H
