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

#include <avogadro/core/vector.h>

#include <vector>

namespace Avogadro {
namespace Rendering {

class Camera;
class GeometryNode;

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
  virtual ~Drawable();

  /**
   * @brief Get a pointer to the drawable object's parent.
   * @return Pointer to the parent node, NULL if no parent.
   */
  const GeometryNode * parent() const { return m_parent; }
  GeometryNode * parent() { return m_parent; }

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
   * @brief Render the contents of the drawable.
   * @param camera The current Camera.
   */
  virtual void render(const Camera &camera);

  /**
   * Clear the contents of the node.
   */
  virtual void clear();

protected:
  friend class GeometryNode;

  /**
   * @brief Set the parent node for the node.
   * @param parent The parent, a value of NULL denotes no parent node.
   */
  void setParent(GeometryNode *parent);

  GeometryNode * m_parent;
  bool m_visible;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_SPHERENODE_H
