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

#ifndef AVOGADRO_RENDERING_GROUPNODE_H
#define AVOGADRO_RENDERING_GROUPNODE_H

#include "node.h"

#include <vector>

namespace Avogadro {
namespace Rendering {

/**
 * @class GroupNode groupnode.h <avogadro/rendering/groupnode.h>
 * @brief The GroupNode class provides common API for grouping child nodes.
 * @author Marcus D. Hanwell
 *
 * The GroupNode may be used to group items together, but for most other
 * purposes a more derived Node type would be the correct choice.
 */

class AVOGADRORENDERING_EXPORT GroupNode : public Node
{
public:
  explicit GroupNode(GroupNode* parent = nullptr);
  ~GroupNode() override;

  /**
   * Accept a visit from our friendly visitor.
   */
  void accept(Visitor&) override;

  /**
   * @brief Add a child node, this node will have its parent set and will be
   * deleted by this node upon destruction.
   * @param node Node to be added.
   */
  void addChild(Node* node);

  /**
   * @brief Remove child node, this node will no longer be deleted.
   * @param node Node to be removed.
   * @return True if the node was removed, false if it was not found.
   */
  bool removeChild(Node* node);

  /**
   * @brief Get the child Node at the specified index.
   * @param index The index of the child.
   * @return A pointer to the child node, or nullptr if the index is out of
   * range.
   */
  Node* child(size_t index);

  /**
   * @brief check if the Node exists in this GroupNode.
   * @param node Node to search.
   * @return True if the node was found, false otherwise.
   */
  bool hasChild(Node* node);

  /**
   * @return The number of child nodes contained by the GroupNode.
   */
  size_t childCount() const { return m_children.size(); }

  /**
   * @brief Get a reference to the child nodes list.
   */
  std::vector<Node*>& children() { return m_children; }
  const std::vector<Node*>& children() const { return m_children; }

  /**
   * @brief Remove all children.
   */
  void clear();

protected:
  std::vector<Node*> m_children;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_GROUPNODE_H
