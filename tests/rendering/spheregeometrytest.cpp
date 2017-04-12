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
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/spheregeometry.h>

using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::SphereGeometry;
using Avogadro::Vector3f;
using Avogadro::Vector3ub;

TEST(SphereGeometryTest, children)
{
  GeometryNode root;
  SphereGeometry* child1 = new SphereGeometry;
  SphereGeometry* child2 = new SphereGeometry;
  root.addDrawable(child1);
  root.addDrawable(child2);

  EXPECT_EQ(&root, child1->parent());
  EXPECT_EQ(&root, child2->parent());
  EXPECT_EQ(child1, root.drawable(0));
  EXPECT_EQ(child2, root.drawable(1));
}

TEST(SphereGeometryTest, removeChild)
{
  GeometryNode root;
  SphereGeometry* child1 = new SphereGeometry;
  SphereGeometry* child2 = new SphereGeometry;
  root.addDrawable(child1);
  root.addDrawable(child2);

  EXPECT_EQ(child1, root.drawable(0));
  EXPECT_EQ(root.removeDrawable(child1), true);
  EXPECT_EQ(root.removeDrawable(child1), false);
  EXPECT_EQ(child2, root.drawable(0));
  EXPECT_EQ(nullptr, child1->parent());
  EXPECT_EQ(&root, child2->parent());
  EXPECT_EQ(root.removeDrawable(child2), true);
  delete child1;
  delete child2;
}

TEST(SphereGeometryTest, addSphere)
{
  SphereGeometry node;
  node.addSphere(Vector3f(1.0, 2.0, 3.0), Vector3ub(200, 100, 50), 5.0);
  EXPECT_EQ(node.size(), static_cast<size_t>(1));
}

TEST(SphereGeometryTest, clear)
{
  SphereGeometry node;
  node.addSphere(Vector3f(1.0, 2.0, 3.0), Vector3ub(200, 100, 50), 5.0);
  EXPECT_EQ(node.size(), static_cast<size_t>(1));
  node.clear();
  EXPECT_EQ(node.size(), static_cast<size_t>(0));
}
