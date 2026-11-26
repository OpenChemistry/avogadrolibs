/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>
#include <avogadro/rendering/visitor.h>

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

namespace {

class CountingVisitor : public Avogadro::Rendering::Visitor
{
public:
  void visit(GroupNode&) override { ++groups; }
  void visit(Avogadro::Rendering::GeometryNode&) override { ++geometries; }
  void visit(Avogadro::Rendering::SphereGeometry&) override { ++spheres; }
  int groups = 0;
  int geometries = 0;
  int spheres = 0;
};

} // namespace

TEST(NodeTest, hiddenNodesHideTheirSubtree)
{
  using Avogadro::Rendering::GeometryNode;
  using Avogadro::Rendering::SphereGeometry;
  GroupNode root;
  auto* group = new GroupNode;
  auto* inner = new GroupNode;
  auto* nested = new GeometryNode;
  auto* direct = new GeometryNode;
  root.addChild(group);
  group->addChild(inner);
  inner->addChild(nested);
  root.addChild(direct);
  nested->addDrawable(new SphereGeometry);
  direct->addDrawable(new SphereGeometry);

  CountingVisitor all;
  root.accept(all);
  EXPECT_EQ(all.groups, 3);
  EXPECT_EQ(all.geometries, 2);
  EXPECT_EQ(all.spheres, 2);

  // The hidden group is not visited itself, nor is anything below it, even
  // the visible group inside it.
  group->setVisible(false);
  EXPECT_TRUE(inner->isVisible());
  CountingVisitor hiddenGroup;
  root.accept(hiddenGroup);
  EXPECT_EQ(hiddenGroup.groups, 1);
  EXPECT_EQ(hiddenGroup.geometries, 1);
  EXPECT_EQ(hiddenGroup.spheres, 1);

  group->setVisible(true);
  direct->setVisible(false);
  CountingVisitor hiddenGeometry;
  root.accept(hiddenGeometry);
  EXPECT_EQ(hiddenGeometry.groups, 3);
  EXPECT_EQ(hiddenGeometry.geometries, 1);
  EXPECT_EQ(hiddenGeometry.spheres, 1);

  direct->setVisible(true);
  CountingVisitor restored;
  root.accept(restored);
  EXPECT_EQ(restored.groups, 3);
  EXPECT_EQ(restored.geometries, 2);
  EXPECT_EQ(restored.spheres, 2);
}
