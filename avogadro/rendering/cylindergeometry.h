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
  CylinderColor(const Vector3f& pos1, const Vector3f& pos2, float r,
                const Vector3ub& c, const Vector3ub& c2 = Vector3ub::Zero())
    : end1(pos1)
    , end2(pos2)
    , radius(r)
    , color(c)
    , color2(c2)
  {}

  Vector3f end1;
  Vector3f end2;
  float radius;
  Vector3ub color;
  Vector3ub color2;
};

/**
 * @class CylinderGeometry cylindergeometry.h
 * <avogadro/rendering/cylindergeometry.h>
 * @brief The CylinderGeometry contains one or more cylinders.
 * @author Marcus D. Hanwell
 */

class AVOGADRORENDERING_EXPORT CylinderGeometry : public Drawable
{
public:
  CylinderGeometry();
  CylinderGeometry(const CylinderGeometry& other);
  ~CylinderGeometry() override;

  CylinderGeometry& operator=(CylinderGeometry);
  friend void swap(CylinderGeometry& lhs, CylinderGeometry& rhs);

  /**
   * Accept a visit from our friendly visitor.
   */
  void accept(Visitor&) override;

  /**
   * @brief Update the VBOs, IBOs etc ready for rendering.
   */
  void update();

  /**
   * @brief Render the cylinder geometry.
   * @param camera The current camera to be used for rendering.
   */
  void render(const Camera& camera) override;

  /**
   * Return the primitives that are hit by the ray.
   * @param rayOrigin Origin of the ray.
   * @param rayEnd End point of the ray.
   * @param rayDirection Normalized direction of the ray.
   * @return Sorted collection of primitives that were hit.
   */
  std::multimap<float, Identifier> hits(
    const Vector3f& rayOrigin, const Vector3f& rayEnd,
    const Vector3f& rayDirection) const override;

  /**
   * @brief Add a cylinder to the geometry object.
   * @param pos1 Base of the cylinder axis.
   * @param pos2 Top of the cylinder axis.
   * @param radius Radius of the cylinder.
   * @param color Color the cylinder will be rendered.
   */
  void addCylinder(const Vector3f& pos1, const Vector3f& pos2, float radius,
                   const Vector3ub& color);

  /**
   * @brief Add a cylinder to the geometry object.
   * @param pos1 Base of the cylinder axis.
   * @param pos2 Top of the cylinder axis.
   * @param radius Radius of the cylinder.
   * @param color1 Color the start of the base of the cylinder.
   * @param color2 Color of the end of the cylinder.
   */
  void addCylinder(const Vector3f& pos1, const Vector3f& pos2, float radius,
                   const Vector3ub& color1, const Vector3ub& color2);

  /**
   * @brief Add a cylinder to the geometry object.
   * @param pos1 Base of the cylinder axis.
   * @param pos2 Top of the cylinder axis.
   * @param radius Radius of the cylinder.
   * @param color Color the cylinder will be rendered.
   * @param index The index of the cylinder being added.
   */
  void addCylinder(const Vector3f& pos1, const Vector3f& pos2, float radius,
                   const Vector3ub& color, size_t index);

  /**
   * @brief Add a cylinder to the geometry object.
   * @param pos1 Base of the cylinder axis.
   * @param pos2 Top of the cylinder axis.
   * @param radius Radius of the cylinder.
   * @param color Color the start of the base of the cylinder.
   * @param color2 Color of the end of the cylinder.
   * @param index The index of the cylinder being added.
   */
  void addCylinder(const Vector3f& pos1, const Vector3f& pos2, float radius,
                   const Vector3ub& color, const Vector3ub& color2,
                   size_t index);

  /**
   * Get a reference to the cylinders.
   */
  std::vector<CylinderColor>& cylinders() { return m_cylinders; }
  const std::vector<CylinderColor>& cylinders() const { return m_cylinders; }

  /**
   * Clear the contents of the node.
   */
  void clear() override;

  /**
   * Get the number of cylinders in the node object.
   */
  size_t size() const { return m_cylinders.size(); }

private:
  std::vector<CylinderColor> m_cylinders;
  std::vector<size_t> m_indices;
  std::map<size_t, size_t> m_indexMap;

  bool m_dirty;

  class Private;
  Private* d;
};

inline CylinderGeometry& CylinderGeometry::operator=(CylinderGeometry other)
{
  using std::swap;
  swap(*this, other);
  return *this;
}

inline void swap(CylinderGeometry& lhs, CylinderGeometry& rhs)
{
  using std::swap;
  swap(static_cast<Drawable&>(lhs), static_cast<Drawable&>(rhs));
  swap(lhs.m_cylinders, rhs.m_cylinders);
  swap(lhs.m_indices, rhs.m_indices);
  swap(lhs.m_indexMap, rhs.m_indexMap);
  lhs.m_dirty = rhs.m_dirty = true;
}

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_CYLINDERGEOMETRY_H
