/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "node.h"

namespace Avogadro::Rendering {

Node::Node() : m_parent(nullptr), m_visible(true)
{
}

Node::~Node()
{
}

void Node::setParent(GroupNode* parent_)
{
  m_parent = parent_;
}

} // End namespace Avogadro
