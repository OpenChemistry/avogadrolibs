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

#ifndef AVOGADRO_RENDERING_GEOMETRYNODE_H
#define AVOGADRO_RENDERING_GEOMETRYNODE_H

#include "node.h"

#include "primitive.h"

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

#include <map>
#include <vector>

namespace Avogadro {
namespace Rendering {

class Camera;
class Drawable;

/**
 * @class GeometryNode geometrynode.h <avogadro/rendering/geometrynode.h>
 * @brief The GeometryNode class is the common base of all geometry nodes.
 * @author Marcus D. Hanwell
 *
 * The GeometryNode contains any Drawable objects, and is the only node type
 * that results in anything being rendered to the screen.
 */

class AVOGADRORENDERING_EXPORT GeometryNode : public Node
{
public:
  GeometryNode();
  ~GeometryNode() override;

  /**
   * Accept a visit from our friendly visitor.
   */
  void accept(Visitor&) override;

  /**
   * @brief Add a drawable object to the geometry node.
   * @param object Drawable object to be added.
   */
  void addDrawable(Drawable* object);

  /**
   * @brief Remove child node, this node will no longer be deleted.
   * @param node Node to be removed.
   * @return True if the node was removed, false if it was not found.
   */
  bool removeDrawable(Drawable* node);

  /**
   * @brief Get the child Node at the specified index.
   * @param index The index of the child.
   * @return A pointer to the child node, or nullptr if the index is out of
   * range.
   */
  Drawable* drawable(size_t index);

  /**
   * @brief Get a reference to the child nodes list.
   */
  std::vector<Drawable*>& drawables() { return m_drawables; }
  const std::vector<Drawable*> drawables() const { return m_drawables; }

  /**
   * @brief Remove all drawable objects.
   */
  void clearDrawables();

  /**
   * @brief Render the drawables in the geometry node.
   */
  void render(const Camera& camera);

  /**
   * Return the primitives that are hit by the ray.
   * @param rayOrigin Origin of the ray.
   * @param rayEnd End point of the ray.
   * @param rayDirection Normalized direction of the ray.
   * @return Sorted collection of primitives that were hit.
   */
  std::multimap<float, Identifier> hits(const Vector3f& rayOrigin,
                                        const Vector3f& rayEnd,
                                        const Vector3f& rayDirection) const;

  /**
   * Return the primitives within the supplied frustrum.
   */
  Core::Array<Identifier> areaHits(const Frustrum& frustrum) const;

protected:
  std::vector<Drawable*> m_drawables;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_GEOMETRYNODE_H
