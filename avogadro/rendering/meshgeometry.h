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

#include <vector>

namespace Avogadro {
namespace Rendering {

struct VertexNormalColor
{
  VertexNormalColor(const Vector3f &vert, const Vector3f &norm,
                    const Vector3ub &c)
    : vertex(vert), normal(norm), color(c) {}
  Vector3f vertex;
  Vector3f normal;
  Vector3ub color;
};

/**
 * @class MeshGeometry meshgeometry.h <avogadro/rendering/meshgeometry.h>
 * @brief The MeshGeometry is used for triangle mesh geometry.
 * @author Marcus D. Hanwell
 */

class AVOGADRORENDERING_EXPORT MeshGeometry : public Drawable
{
public:
  MeshGeometry();
  ~MeshGeometry();

  /**
   * @brief Update the VBOs, IBOs etc ready for rendering.
   */
  void update();

  /**
   * @brief Render the mesh geometry.
   * @param camera The current camera to be used for rendering.
   */
  void render(const Camera &camera);

  /**
   * Add one or more triangles to the drawable object, the color array can be
   * NULL if per-vertex coloring is not desired.
   */
  void addTriangles(const Vector3f *vertices, const Vector3f *normals,
                    const Vector3ub *colors, size_t n);

  /**
   * Get a reference to the spheres.
   */
  std::vector<VertexNormalColor>& vertices() { return m_vertices; }
  const std::vector<VertexNormalColor>& vertices() const { return m_vertices; }

  /**
   * Clear the contents of the node.
   */
  void clear();

  /**
   * Get the number of spheres in the node object.
   */
  size_t size() const { return m_vertices.size(); }

  /**
   * Set the color of the mesh.
   */
  void setColor(const Vector3ub &c) { m_color = c; }

  /**
   * @return The current mesh color.
   */
  Vector3ub color() const { return m_color; }

  /**
   * Set the opacity of the mesh.
   */
  void setOpacity(unsigned int opacity_) { m_opacity = opacity_; }

  /**
   * @return The current opacity of the mesh.
   */
  unsigned int opacity() const { return m_opacity; }

private:
  std::vector<VertexNormalColor> m_vertices;
  std::vector<size_t> m_indices;
  Vector3ub m_color;
  unsigned char m_opacity;

  bool m_dirty;

  class Private;
  Private *d;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_MESHGEOMETRY_H
