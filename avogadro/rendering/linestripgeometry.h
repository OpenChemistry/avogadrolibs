/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_RENDERING_LINESTRIPGEOMETRY_H
#define AVOGADRO_RENDERING_LINESTRIPGEOMETRY_H

#include "drawable.h"

#include <avogadro/core/array.h>

namespace Avogadro {
namespace Rendering {

/**
 * @class LineStripGeometry linestripgeometry.h
 * <avogadro/rendering/linestripgeometry.h>
 * @brief The LineStripGeometry class is used to store sets of line strips.
 */

class AVOGADRORENDERING_EXPORT LineStripGeometry : public Drawable
{
public:
  struct PackedVertex
  {                  // 16 bytes total:
    Vector3f vertex; // 12 bytes
    Vector4ub color; //  4 bytes

    PackedVertex(const Vector3f& v, const Vector4ub& c)
      : vertex(v)
      , color(c)
    {}
    static int vertexOffset() { return 0; }
    static int colorOffset() { return static_cast<int>(sizeof(Vector3f)); }
  };

  static const size_t InvalidIndex;

  LineStripGeometry();
  LineStripGeometry(const LineStripGeometry& other);
  ~LineStripGeometry() override;

  LineStripGeometry& operator=(LineStripGeometry);
  friend void swap(LineStripGeometry& lhs, LineStripGeometry& rhs);

  /**
   * Accept a visit from our friendly visitor.
   */
  void accept(Visitor&) override;

  /**
   * @brief Render the line strips.
   * @param camera The current camera to be used for rendering.
   */
  void render(const Camera& camera) override;

  /**
   * Clear the contents of the node.
   */
  void clear() override;

  /**
   * Add a complete line strip to the object.
   * @param vertices The 3D vertices which will be connected to form the line
   * strip.
   * @param color Vertex color. If not specified, use the current color() and
   * opacity(). If the 3 component color is set, the current opacity() is used.
   * @param lineWidth The width of the line strip.
   * @note All arrays must be the same length, or this function call will fail,
   * returning InvalidIndex.
   * @return The index of the first vertex added by this call.
   * @{
   */
  size_t addLineStrip(const Core::Array<Vector3f>& vertices,
                      const Core::Array<Vector4ub>& color, float lineWidth);
  size_t addLineStrip(const Core::Array<Vector3f>& vertices,
                      const Core::Array<Vector3ub>& color, float lineWidth);
  size_t addLineStrip(const Core::Array<Vector3f>& vertices, float lineWidth);
  /** @} */

  /**
   * The default color of the lines. This is used to set the color of new
   * vertices when no explicit vertex color is specified.
   * @{
   */
  void setColor(const Vector3ub& c) { m_color = c; }
  Vector3ub color() const { return m_color; }
  /** @} */

  /**
   * The default opacity of the lines. This is used when either no explicit
   * vertex color is specified, or a three component color is used.
   * @{
   */
  void setOpacity(unsigned char opacity_) { m_opacity = opacity_; }
  unsigned char opacity() const { return m_opacity; }
  /** @} */

  /** The vertex array. */
  Core::Array<PackedVertex> vertices() const { return m_vertices; }

private:
  /**
   * @brief Update the VBOs, IBOs etc ready for rendering.
   */
  void update();

  Core::Array<PackedVertex> m_vertices;
  Core::Array<unsigned int> m_lineStarts;
  Core::Array<float> m_lineWidths;

  Vector3ub m_color;
  unsigned char m_opacity;

  bool m_dirty;

  class Private;
  Private* d;
};

inline LineStripGeometry& LineStripGeometry::operator=(LineStripGeometry other)
{
  using std::swap;
  swap(*this, other);
  return *this;
}

inline void swap(LineStripGeometry& lhs, LineStripGeometry& rhs)
{
  using std::swap;
  swap(static_cast<Drawable&>(lhs), static_cast<Drawable&>(rhs));
  swap(lhs.m_vertices, rhs.m_vertices);
  swap(lhs.m_lineStarts, rhs.m_lineStarts);
  swap(lhs.m_lineWidths, rhs.m_lineWidths);
  swap(lhs.m_color, rhs.m_color);
  swap(lhs.m_opacity, rhs.m_opacity);
  lhs.m_dirty = rhs.m_dirty = true;
}

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_LINESTRIPGEOMETRY_H
