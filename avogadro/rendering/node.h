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

#ifndef AVOGADRO_RENDERING_NODE_H
#define AVOGADRO_RENDERING_NODE_H

#include "avogadrorenderingexport.h"

#include <vector>

namespace Avogadro {
namespace Rendering {

/**
 * @class Node node.h <avogadro/rendering/node.h>
 * @brief The Node class is the base class for all items in the scene.
 * @author Marcus D. Hanwell
 *
 * The Node class is the base class for nodes in the Scene, providing common
 * API and functionality. The Node class may be used to group items together,
 * but for most other purposes a more derived Node type would be the correct
 * choice.
 */

class AVOGADRORENDERING_EXPORT Node
{
public:
  explicit Node(Node *parent = 0);
  virtual ~Node();

  /**
   * @brief Set the parent node for the node.
   * @param parent The parent, a value of NULL denotes no parent node.
   */
  void setParent(Node *parent);

  /**
   * @brief Get a pointer to the node's parent.
   * @return Pointer to the parent node, NULL if no parent.
   */
  const Node * parent() const { return m_parent; }
  Node * parent() { return m_parent; }

  /**
   * @brief Set the visibility of the node.
   * @param vis True if the node is visible, false if invisible.
   */
  void setVisible(bool vis) { m_visible = vis; }

  /**
   * @brief Get the current visibility of the node.
   * @return True if visible.
   */
  bool isVisible() const { return m_visible; }

  /**
   * @brief Add a child node, this node will have its parent set and will be
   * deleted by this node upon destruction.
   * @param node Node to be added.
   */
  void addChild(Node *node);

  /**
   * @brief Remove child node, this node will no longer be deleted.
   * @param node Node to be removed.
   * @return True if the node was removed, false if it was not found.
   */
  bool removeChild(Node *node);

  /**
   * @brief Get the child Node at the specified index.
   * @param index The index of the child.
   * @return A pointer to the child node, or NULL if the index is out of range.
   */
  Node * child(size_t index);

protected:
  Node * m_parent;
  bool m_visible;
  std::vector<Node *> m_children;

};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_NODE_H
