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

#include "groupnode.h"
#include "visitor.h"

namespace Avogadro {
namespace Rendering {

GroupNode::GroupNode(GroupNode *parent_)
{
  if (parent_)
    parent_->addChild(this);
}

GroupNode::~GroupNode()
{
  // Like all good parents, we destroy our children before we go...
  clear();
}

void GroupNode::accept(Visitor &visitor)
{
  visitor.visit(*this);
  for (std::vector<Node *>::iterator it = m_children.begin();
       it != m_children.end(); ++it) {
    (*it)->accept(visitor);
  }
}

void GroupNode::addChild(Node *node)
{
  if (!node || node == this)
    return;
  for (std::vector<Node *>::const_iterator it = m_children.begin();
       it != m_children.end(); ++it) {
    if (*it == node)
      return;
  }
  node->setParent(this);
  m_children.push_back(node);
}

bool GroupNode::removeChild(Node *node)
{
  if (!node)
    return false;
  for (std::vector<Node *>::iterator it = m_children.begin();
       it != m_children.end(); ++it) {
    if (*it == node) {
      (*it)->setParent(nullptr);
      m_children.erase(it);
      return true;
    }
  }
  return false;
}

Node * GroupNode::child(size_t index)
{
  if (index >= m_children.size())
    return nullptr;
  else
    return m_children[index];
}

void GroupNode::clear()
{
  // Like all good parents, we destroy our children before we go...
  for (std::vector<Node *>::const_iterator it = m_children.begin();
       it != m_children.end(); ++it) {
    delete (*it);
  }
  m_children.clear();
}

} // End namespace Rendering
} // End namespace Avogadro
