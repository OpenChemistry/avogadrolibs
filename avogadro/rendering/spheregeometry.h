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

#ifndef AVOGADRO_RENDERING_SPHEREGEOMETRY_H
#define AVOGADRO_RENDERING_SPHEREGEOMETRY_H

#include "drawable.h"

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

namespace Avogadro {
namespace Rendering {

struct SphereColor
{
  SphereColor(Vector3f centre, float r, Vector3ub c)
    : center(centre), radius(r), color(c)
  {}
  Vector3f center;
  float radius;
  Vector3ub color;
};

/**
 * @class SphereGeometry spheregeometry.h <avogadro/rendering/spheregeometry.h>
 * @brief The SphereGeometry class contains one or more spheres.
 * @author Marcus D. Hanwell
 *
 * This Drawable is capable of storing the geometry for one or more spheres.
 * A sphere is defined by a center point, a radius and a color. If the
 * spheres are not a densely packed one-to-one mapping with the objects indices
 * they can also optionally use an identifier that will point to some numeric
 * ID for the purposes of picking.
 */

class AVOGADRORENDERING_EXPORT SphereGeometry : public Drawable
{
public:
  SphereGeometry();
  SphereGeometry(const SphereGeometry& other);
  ~SphereGeometry() override;

  SphereGeometry& operator=(SphereGeometry);
  friend void swap(SphereGeometry& lhs, SphereGeometry& rhs);

  /**
   * Accept a visit from our friendly visitor.
   */
  void accept(Visitor&) override;

  /**
   * @brief Update the VBOs, IBOs etc ready for rendering.
   */
  void update();

  /**
   * @brief Render the sphere geometry.
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
   * Return the primitives within the supplied frustrum.
   */
  Core::Array<Identifier> areaHits(const Frustrum& f) const override;

  /**
   * Set the opacity of the spheres in this group.
   */
  void setOpacity(float o)
  {
    m_opacity = o;
    if (o < 1.0f)
      setRenderPass(TranslucentPass);
  }

  /**
   * Add a sphere to the geometry object.
   */
  void addSphere(const Vector3f& position, const Vector3ub& color, float radius,
                 size_t index = MaxIndex);

  /**
   * Get a reference to the spheres.
   */
  Core::Array<SphereColor>& spheres() { return m_spheres; }
  const Core::Array<SphereColor>& spheres() const { return m_spheres; }

  /**
   * Clear the contents of the node.
   */
  void clear() override;

  /**
   * Get the number of spheres in the node object.
   */
  size_t size() const { return m_spheres.size(); }

private:
  Core::Array<SphereColor> m_spheres;
  Core::Array<size_t> m_indices;

  bool m_dirty;

  float m_opacity = 1.0f;

  class Private;
  Private* d;
};

inline SphereGeometry& SphereGeometry::operator=(SphereGeometry other)
{
  using std::swap;
  swap(*this, other);
  return *this;
}

inline void swap(SphereGeometry& lhs, SphereGeometry& rhs)
{
  using std::swap;
  swap(static_cast<Drawable&>(lhs), static_cast<Drawable&>(rhs));
  swap(lhs.m_spheres, rhs.m_spheres);
  swap(lhs.m_indices, rhs.m_indices);
  lhs.m_dirty = rhs.m_dirty = true;
}

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_SPHEREGEOMETRY_H
