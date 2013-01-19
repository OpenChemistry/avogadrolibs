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

#include "node.h"

namespace Avogadro {
namespace Rendering {

Node::Node(Node *parent_) : m_parent(NULL), m_visible(true)
{
  if (parent_ && parent_ != this)
    parent_->addChild(this);
}

Node::~Node()
{
  // Like all good parents, we destroy our children before we go...
  for (std::vector<Node *>::const_iterator it = m_children.begin();
       it != m_children.end(); ++it) {
    delete (*it);
  }
}

void Node::setParent(Node *parent)
{
  if (parent == this)
    return;
  if (!parent)
    m_parent = NULL;
  m_parent->addChild(parent);
}

void Node::addChild(Node *node)
{
  if (!node || node == this)
    return;
  for (std::vector<Node *>::const_iterator it = m_children.begin();
       it != m_children.end(); ++it) {
    if (*it == node)
      return;
  }
  node->m_parent = this;
  m_children.push_back(node);
}

bool Node::removeChild(Node *node)
{
  if (!node)
    return false;
  for (std::vector<Node *>::iterator it = m_children.begin();
       it != m_children.end(); ++it) {
    if (*it == node) {
      (*it)->setParent(NULL);
      m_children.erase(it);
      return true;
    }
  }
  return false;
}

Node * Node::child(size_t index)
{
  if (index >= m_children.size())
    return NULL;
  else
    return m_children[index];
}

} // End namespace Rendering
} // End namespace Avogadro
