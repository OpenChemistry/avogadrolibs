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

#ifndef AVOGADRO_RENDERING_DRAWABLE_H
#define AVOGADRO_RENDERING_DRAWABLE_H

#include "avogadrorenderingexport.h"

#include "avogadrorendering.h"
#include "primitive.h"

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

#include <map>

namespace Avogadro {
namespace Rendering {

class Camera;
class GeometryNode;
class Visitor;

/**
 * @class Drawable drawable.h <avogadro/rendering/drawable.h>
 * @brief The base class for all drawable geometry and types.
 * @author Marcus D. Hanwell
 *
 * This class provides the common API for drawable objects on the scene. It is
 * not a Node object, and can only be attached to GeometryNode objects in the
 * Scene.
 */

class AVOGADRORENDERING_EXPORT Drawable
{
public:
  Drawable();
  Drawable(const Drawable& other);
  virtual ~Drawable();

  Drawable& operator=(Drawable);
  friend void swap(Drawable& lhs, Drawable& rhs);

  /**
   * Accept a visit from our friendly visitor.
   */
  virtual void accept(Visitor&);

  /**
   * @brief Get a pointer to the drawable object's parent.
   * @return Pointer to the parent node, nullptr if no parent.
   */
  const GeometryNode* parent() const { return m_parent; }
  GeometryNode* parent() { return m_parent; }

  /**
   * @brief Set the visibility of the drawable object.
   * @param visibility True if the drawable is visible, false if invisible.
   */
  void setVisible(bool visibility) { m_visible = visibility; }

  /**
   * @brief Get the current visibility of the drawable.
   * @return True if visible.
   */
  bool isVisible() const { return m_visible; }

  /**
   * The render pass in which this drawable should be rendered.
   * @sa Rendering::RenderPass
   * @{
   */
  void setRenderPass(RenderPass pass) { m_renderPass = pass; }
  RenderPass renderPass() const { return m_renderPass; }
  /** @} */

  /**
   * @brief Render the contents of the drawable.
   * @param camera The current Camera.
   */
  virtual void render(const Camera& camera);

  /**
   * Get the identifier for the object, this stores the parent Molecule and
   * the type represented by the geometry.
   */
  Identifier& identifier() { return m_identifier; }
  const Identifier& identifier() const { return m_identifier; }

  /**
   * Return the primitives that are hit by the ray.
   * @param rayOrigin Origin of the ray.
   * @param rayEnd End point of the ray.
   * @param rayDirection Normalized direction of the ray.
   * @return Sorted collection of primitives that were hit.
   */
  virtual std::multimap<float, Identifier> hits(
    const Vector3f& rayOrigin, const Vector3f& rayEnd,
    const Vector3f& rayDirection) const;

  /**
   * Return the primitives within the supplied area.
   * @param f The frustrum defining the area highlighted.
   * @return Collection of primitives in the area.
   */
  virtual Core::Array<Identifier> areaHits(const Frustrum& f) const;

  /**
   * Clear the contents of the node.
   */
  virtual void clear();

protected:
  friend class GeometryNode;

  /**
   * @brief Set the parent node for the node.
   * @param parent The parent, a value of nullptr denotes no parent node.
   */
  void setParent(GeometryNode* parent);

  GeometryNode* m_parent;
  bool m_visible;
  RenderPass m_renderPass;
  Identifier m_identifier;
};

inline Drawable& Drawable::operator=(Drawable rhs)
{
  using std::swap;
  swap(*this, rhs);
  return *this;
}

inline void swap(Drawable& lhs, Drawable& rhs)
{
  using std::swap;
  swap(lhs.m_parent, rhs.m_parent);
  swap(lhs.m_visible, rhs.m_visible);
  swap(lhs.m_renderPass, rhs.m_renderPass);
  swap(lhs.m_identifier, rhs.m_identifier);
}

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_SPHERENODE_H
