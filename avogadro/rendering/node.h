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
#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace Rendering {

class GroupNode;
class Visitor;

/**
 * @class Node node.h <avogadro/rendering/node.h>
 * @brief The Node class is the base class for all items in the scene.
 * @author Marcus D. Hanwell
 *
 * The Node class is the base class for nodes in the Scene, providing common
 * API and functionality.
 */

class AVOGADRORENDERING_EXPORT Node
{
public:
  Node();
  virtual ~Node();

  /**
   * Accept a visit from our friendly visitor.
   */
  virtual void accept(Visitor&) { return; }

  /**
   * @brief Get a pointer to the node's parent.
   * @return Pointer to the parent node, nullptr if no parent.
   */
  const GroupNode* parent() const { return m_parent; }
  GroupNode* parent() { return m_parent; }

  /**
   * @brief Set the visibility of the node.
   * @param visibility True if the node is visible, false if invisible.
   */
  void setVisible(bool visibility) { m_visible = visibility; }

  /**
   * @brief Get the current visibility of the node.
   * @return True if visible.
   */
  bool isVisible() const { return m_visible; }

  /**
   * @brief Attempt to dynamic_cast to specified node type.
   * @return Valid pointer to specified type, or null.
   */
  template <typename T>
  T* cast();
  template <typename T>
  const T* cast() const;

protected:
  friend class GroupNode;

  /**
   * @brief Set the parent node for the node.
   * @param parent The parent, a value of nullptr denotes no parent node.
   */
  void setParent(GroupNode* parent);

  GroupNode* m_parent;
  bool m_visible;
};

template <typename T>
T* Node::cast()
{
  return dynamic_cast<T*>(this);
}

template <typename T>
const T* Node::cast() const
{
  return dynamic_cast<const T*>(this);
}

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_NODE_H
