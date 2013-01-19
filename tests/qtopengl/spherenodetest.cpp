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

#include <gtest/gtest.h>

#include <avogadro/core/vector.h>
#include <avogadro/rendering/spherenode.h>

#include <iostream>

using Avogadro::Rendering::Node;
using Avogadro::Rendering::SphereNode;
using Avogadro::Vector3f;
using Avogadro::Vector3ub;

TEST(SphereNodeTest, children)
{
  Node root;
  SphereNode *child1 = new SphereNode;
  SphereNode *child2 = new SphereNode;
  root.addChild(child1);
  root.addChild(child2);

  EXPECT_EQ(&root, child1->parent());
  EXPECT_EQ(&root, child2->parent());
  EXPECT_EQ(child1, root.child(0));
  EXPECT_EQ(child2, root.child(1));
}

TEST(SphereNodeTest, parents)
{
  Node root;
  SphereNode *child1 = new SphereNode(&root);
  SphereNode *child2 = new SphereNode(&root);

  EXPECT_EQ(&root, child1->parent());
  EXPECT_EQ(&root, child2->parent());
  EXPECT_EQ(child1, root.child(0));
  EXPECT_EQ(child2, root.child(1));
}

TEST(SphereNodeTest, removeChild)
{
  Node root;
  SphereNode *child1 = new SphereNode(&root);
  SphereNode *child2 = new SphereNode(&root);

  EXPECT_EQ(child1, root.child(0));
  EXPECT_EQ(root.removeChild(child1), true);
  EXPECT_EQ(root.removeChild(child1), false);
  EXPECT_EQ(child2, root.child(0));
  EXPECT_EQ(NULL, child1->parent());
  EXPECT_EQ(&root, child2->parent());
  EXPECT_EQ(root.removeChild(child2), true);
  delete child1;
}

TEST(SphereNodeTest, addSphere)
{
  SphereNode node;
  node.addSphere(Vector3f(1.0, 2.0, 3.0), Vector3ub(200, 100, 50), 5.0);
  EXPECT_EQ(node.size(), static_cast<size_t>(1));
}

TEST(SphereNodeTest, clear)
{
  SphereNode node;
  node.addSphere(Vector3f(1.0, 2.0, 3.0), Vector3ub(200, 100, 50), 5.0);
  EXPECT_EQ(node.size(), static_cast<size_t>(1));
  node.clear();
  EXPECT_EQ(node.size(), static_cast<size_t>(0));
}
