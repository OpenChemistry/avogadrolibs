/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/vector.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <cstddef>
#include <cstring>
#include <type_traits>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::SphereColor;
using Avogadro::Rendering::SphereGeometry;

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

// spheres() is uploaded to the GPU as the per-instance buffer, so the byte
// layout is a contract with the vertex shader: center (3 floats) at 0, radius
// (float) at 12, color (3 unsigned bytes) at 16, stride 20.
TEST(SphereGeometryTest, instanceLayout)
{
  static_assert(std::is_standard_layout_v<SphereColor>);
  EXPECT_EQ(sizeof(SphereColor), static_cast<size_t>(20));
  EXPECT_EQ(offsetof(SphereColor, center), static_cast<size_t>(0));
  EXPECT_EQ(offsetof(SphereColor, radius), static_cast<size_t>(12));
  EXPECT_EQ(offsetof(SphereColor, color), static_cast<size_t>(16));
}

TEST(SphereGeometryTest, instanceBytes)
{
  SphereGeometry node;
  node.addSphere(Vector3f(1.0f, 2.0f, 3.0f), Vector3ub(200, 100, 50), 1.5f);
  node.addSphere(Vector3f(-4.0f, 5.0f, -6.0f), Vector3ub(1, 2, 3), 0.25f);

  const auto& spheres = node.spheres();
  ASSERT_EQ(spheres.size(), static_cast<size_t>(2));
  // The array is contiguous, so the upload sees the instances back to back.
  const auto* bytes = reinterpret_cast<const unsigned char*>(&spheres[0]);
  float values[4];
  std::memcpy(values, bytes + sizeof(SphereColor), 3 * sizeof(float));
  std::memcpy(values + 3, bytes + sizeof(SphereColor) + 12, sizeof(float));
  EXPECT_EQ(values[0], -4.0f);
  EXPECT_EQ(values[1], 5.0f);
  EXPECT_EQ(values[2], -6.0f);
  EXPECT_EQ(values[3], 0.25f);
  EXPECT_EQ(bytes[16], 200);
  EXPECT_EQ(bytes[17], 100);
  EXPECT_EQ(bytes[18], 50);
  EXPECT_EQ(bytes[sizeof(SphereColor) + 16], 1);
  EXPECT_EQ(bytes[sizeof(SphereColor) + 18], 3);
}
