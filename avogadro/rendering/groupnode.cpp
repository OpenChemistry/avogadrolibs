/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "groupnode.h"
#include "visitor.h"

namespace Avogadro::Rendering {

GroupNode::GroupNode(GroupNode* parent_)
{
  if (parent_)
    parent_->addChild(this);
}

GroupNode::~GroupNode()
{
  // Like all good parents, we destroy our children before we go...
  clear(ALL);
}

void GroupNode::accept(Visitor& visitor)
{
  visitor.visit(*this);
  for (auto & it : m_children) {
    it.node->accept(visitor);
  }
}

void GroupNode::addChild(Node* node, NodeType ui)
{
  if (!node || node == this)
    return;
  if (!hasChild(node)) {
    node->setParent(this);
    m_children.emplace_back(node, ui);
  }
}

bool GroupNode::hasChild(Node* node) const
{
  if (!node)
    return false;
  for (auto it : m_children) {
    if (it.node == node) {
      return true;
    }
  }
  return false;
}

bool GroupNode::removeChild(Node* node)
{
  if (!node)
    return false;
  for (auto it = m_children.begin(); it != m_children.end(); ++it) {
    if (it->node == node) {
      it->node->setParent(nullptr);
      m_children.erase(it);
      return true;
    }
  }
  return false;
}

Node* GroupNode::child(size_t index)
{
  if (index >= m_children.size())
    return nullptr;
  else {
    // this is only used in test so we can us a O(n) function
    auto it = m_children.begin();
    it = std::next(it, index);
    return it->node;
  }
}

void GroupNode::clear(NodeType ui)
{
  // Like all good parents, we destroy our children before we go...
  for (auto it = m_children.begin(); it != m_children.end();) {
    auto itNext = std::next(it);
    if (it->ui == ui || ui == ALL) {
      auto groupNode = it->node->cast<GroupNode>();
      if (groupNode != nullptr && ui != ALL) {
        switch (ui) {
          case UI:
            groupNode->clearUI();
            break;
          default:
          case GEOMETRY:
            groupNode->clear();
            break;
        }
        // like a good parent, kill your son if you don't have nieces
        if (groupNode->childCount() == 0) {
          delete it->node;
          m_children.erase(it);
        }
      } else {
        delete it->node;
        m_children.erase(it);
      }
    }
    it = itNext;
  }
}

void GroupNode::clear()
{
  clear(GEOMETRY);
}

void GroupNode::clearUI()
{
  clear(UI);
}

} // End namespace Avogadro
