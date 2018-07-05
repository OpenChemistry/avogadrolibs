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

#ifndef AVOGADRO_RENDERING_MESHGEOMETRY_H
#define AVOGADRO_RENDERING_MESHGEOMETRY_H

#include "drawable.h"

#include <avogadro/core/array.h>

namespace Avogadro {
namespace Rendering {

/**
 * @class MeshGeometry meshgeometry.h <avogadro/rendering/meshgeometry.h>
 * @brief The MeshGeometry is used for triangle mesh geometry.
 * @author Marcus D. Hanwell
 */

class AVOGADRORENDERING_EXPORT MeshGeometry : public Drawable
{
public:
  struct PackedVertex
  {
    Vector4ub color;          //  4 bytes
    Vector3f normal;          // 12 bytes
    Vector3f vertex;          // 12 bytes
    unsigned char padding[4]; //  4 bytes

    PackedVertex(const Vector4ub& c, const Vector3f& n, const Vector3f& v)
      : color(c)
      , normal(n)
      , vertex(v)
    {}

    static int colorOffset() { return 0; }
    static int normalOffset() { return static_cast<int>(sizeof(Vector4ub)); }
    static int vertexOffset()
    {
      return normalOffset() + static_cast<int>(sizeof(Vector3f));
    }
  }; // 32 bytes total size - 16/32/64 are ideal for alignment.

  static const unsigned int InvalidIndex;

  MeshGeometry();
  MeshGeometry(const MeshGeometry& other);
  ~MeshGeometry() override;

  MeshGeometry& operator=(MeshGeometry);
  friend void swap(MeshGeometry& lhs, MeshGeometry& rhs);

  /**
   * Accept a visit from our friendly visitor.
   */
  void accept(Visitor&) override;

  /**
   * @brief Render the mesh geometry.
   * @param camera The current camera to be used for rendering.
   */
  void render(const Camera& camera) override;

  /**
   * Add vertices to the object. Note that this just adds vertices to the
   * object. Use addTriangles with size_t indices to actually draw them.
   * @param vertices The 3D vertex points to add to the drawable.
   * @param normals The normal direction at the vertex.
   * @param colors Vertex color. If not specified, use the current color() and
   * opacity(). If the 3 component color is set, the current opacity() is used.
   * @note All arrays must be the same length, or this function call will fail,
   * returning InvalidIndex.
   * @return The index of the first vertex added by this call, used to specify
   * element arrays for the actual triangles.
   * @{
   */
  unsigned int addVertices(const Core::Array<Vector3f>& vertices,
                           const Core::Array<Vector3f>& normals,
                           const Core::Array<Vector4ub>& colors);
  unsigned int addVertices(const Core::Array<Vector3f>& vertices,
                           const Core::Array<Vector3f>& normals,
                           const Core::Array<Vector3ub>& colors);
  unsigned int addVertices(const Core::Array<Vector3f>& vertices,
                           const Core::Array<Vector3f>& normals);
  /** @} */

  /**
   * Add triangles to the mesh. Triangles are specified as 3-tuples of vertex
   * indices. Must call addVertices first, and use the return value to obtain
   * the valid index range.
   * @{
   */
  void addTriangle(unsigned int index1, unsigned int index2,
                   unsigned int index3);
  void addTriangles(const Core::Array<unsigned int>& indices);
  /** @} */

  /**
   * Clear the contents of the node.
   */
  void clear() override;

  /**
   * Get the number of vertices.
   */
  size_t vertexCount() const { return m_vertices.size(); }

  /**
   * Get the number of vertices.
   */
  size_t indexCount() const { return m_indices.size(); }

  /**
   * Get the number of triangles.
   */
  size_t triangleCount() const { return m_indices.size() / 3; }

  /**
   * The default color of the mesh. This is used to set the color of new
   * vertices when no explicit vertex color is specified.
   * @{
   */
  void setColor(const Vector3ub& c) { m_color = c; }
  Vector3ub color() const { return m_color; }
  /** @} */

  /**
   * The default opacity of the mesh. This is used when either no explicit
   * vertex color is specified, or a three component color is used.
   * @{
   */
  void setOpacity(unsigned char opacity_) { m_opacity = opacity_; }
  unsigned char opacity() const { return m_opacity; }
  /** @} */

  Core::Array<PackedVertex> vertices() { return m_vertices; }
  Core::Array<unsigned int> triangles() { return m_indices; }

private:
  /**
   * @brief Update the VBOs, IBOs etc ready for rendering.
   */
  void update();

  Core::Array<PackedVertex> m_vertices;
  Core::Array<unsigned int> m_indices;
  Vector3ub m_color;
  unsigned char m_opacity;

  bool m_dirty;

  class Private;
  Private* d;
};

inline MeshGeometry& MeshGeometry::operator=(MeshGeometry other)
{
  using std::swap;
  swap(*this, other);
  return *this;
}

inline void swap(MeshGeometry& lhs, MeshGeometry& rhs)
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

#endif // AVOGADRO_RENDERING_MESHGEOMETRY_H
