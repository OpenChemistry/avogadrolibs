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

#ifndef AVOGADRO_RENDERING_CYLINDERGEOMETRY_H
#define AVOGADRO_RENDERING_CYLINDERGEOMETRY_H

#include "drawable.h"

#include <vector>

namespace Avogadro {
namespace Rendering {

struct CylinderColor
{
  CylinderColor(const Vector3f &pos, const Vector3f &dir,
                float l, float r, const Vector3ub &c)
    : position(pos), direction(dir), length(l), radius(r), color(c) {}
  Vector3f position;
  Vector3f direction;
  float length;
  float radius;
  Vector3ub color;
};

/**
 * @class CylinderGeometry cylindergeometry.h <avogadro/rendering/cylindergeometry.h>
 * @brief The CylinderGeometry contains one or more cylinders.
 * @author Marcus D. Hanwell
 */

class AVOGADRORENDERING_EXPORT CylinderGeometry : public Drawable
{
public:
  CylinderGeometry();
  ~CylinderGeometry();

  /**
   * Accept a visit from our friendly visitor.
   */
  void accept(Visitor &) AVO_OVERRIDE;

  /**
   * @brief Update the VBOs, IBOs etc ready for rendering.
   */
  void update();

  /**
   * @brief Render the sphere geometry.
   * @param camera The current camera to be used for rendering.
   */
  void render(const Camera &camera);

  /**
   * Return the primitives that are hit by the ray.
   * @param rayOrigin Origin of the ray.
   * @param rayEnd End point of the ray.
   * @param rayDirection Normalized direction of the ray.
   * @return Sorted collection of primitives that were hit.
   */
  std::multimap<float, Identifier> hits(const Vector3f &rayOrigin,
                                        const Vector3f &rayEnd,
                                        const Vector3f &rayDirection) const;

  /**
   * Add a sphere to the geometry object.
   */
  void addCylinder(const Vector3f &position, const Vector3f &direction,
                   float length, float radius, const Vector3ub &color);
  void addCylinder(const Vector3f &position, const Vector3f &direction,
                   float length, float radius, const Vector3ub &color,
                   size_t index);

  /**
   * Get a reference to the spheres.
   */
  std::vector<CylinderColor>& cylinders() { return m_cylinders; }
  const std::vector<CylinderColor>& cylinders() const { return m_cylinders; }

  /**
   * Clear the contents of the node.
   */
  void clear();

  /**
   * Get the number of spheres in the node object.
   */
  size_t size() const { return m_cylinders.size(); }

private:
  std::vector<CylinderColor> m_cylinders;
  std::vector<size_t> m_indices;
  std::map<size_t, size_t> m_indexMap;

  bool m_dirty;

  class Private;
  Private *d;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_CYLINDERGEOMETRY_H
