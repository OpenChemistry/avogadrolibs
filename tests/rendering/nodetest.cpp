/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/rendering/groupnode.h>

using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::Node;

TEST(NodeTest, children)
{
  GroupNode root;
  Node* child1 = new Node;
  Node* child2 = new Node;
  root.addChild(child1);
  root.addChild(child2);

  EXPECT_EQ(&root, child1->parent());
  EXPECT_EQ(&root, child2->parent());
  EXPECT_EQ(child1, root.child(0));
  EXPECT_EQ(child2, root.child(1));
}

TEST(NodeTest, removeChild)
{
  GroupNode root;
  Node* child1 = new Node;
  Node* child2 = new Node;
  root.addChild(child1);
  root.addChild(child2);

  EXPECT_EQ(child1, root.child(0));
  EXPECT_EQ(root.removeChild(child1), true);
  EXPECT_EQ(root.removeChild(child1), false);
  EXPECT_EQ(child2, root.child(0));
  EXPECT_EQ(nullptr, child1->parent());
  EXPECT_EQ(&root, child2->parent());
  EXPECT_EQ(root.removeChild(child2), true);
  delete child1;
  delete child2;
}
