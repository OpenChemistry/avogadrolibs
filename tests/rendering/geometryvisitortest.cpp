/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/geometryvisitor.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/meshgeometry.h>
#include <avogadro/rendering/spheregeometry.h>

#include <limits>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Core::Array;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GeometryVisitor;
using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::MeshGeometry;
using Avogadro::Rendering::SphereGeometry;

namespace {

// Add two points (and trivial normals) to the mesh.
void addPoints(MeshGeometry* mesh, const Vector3f& a, const Vector3f& b)
{
  Array<Vector3f> verts;
  Array<Vector3f> normals;
  verts.push_back(a);
  verts.push_back(b);
  normals.push_back(Vector3f::UnitZ());
  normals.push_back(Vector3f::UnitZ());
  EXPECT_NE(MeshGeometry::InvalidIndex, mesh->addVertices(verts, normals));
}

} // namespace

TEST(GeometryVisitorTest, meshOnlyScene)
{
  GeometryNode root;
  auto* mesh = new MeshGeometry;
  root.addDrawable(mesh);
  addPoints(mesh, Vector3f(10.f, 0.f, 0.f), Vector3f(14.f, 6.f, 12.f));

  GeometryVisitor visitor;
  root.accept(visitor);

  EXPECT_NEAR(12.f, visitor.center().x(), 1e-5f);
  EXPECT_NEAR(3.f, visitor.center().y(), 1e-5f);
  EXPECT_NEAR(6.f, visitor.center().z(), 1e-5f);
  // Half the box diagonal: 0.5 * sqrt(4^2 + 6^2 + 12^2) = 7
  EXPECT_NEAR(7.f, visitor.radius(), 1e-5f);
}

TEST(GeometryVisitorTest, meshAndSpheres)
{
  GroupNode root;
  auto* geometry = new GeometryNode;
  root.addChild(geometry);

  auto* spheres = new SphereGeometry;
  spheres->addSphere(Vector3f(0.f, 0.f, 0.f), Vector3ub(255, 0, 0), 1.f);
  geometry->addDrawable(spheres);

  auto* mesh = new MeshGeometry;
  geometry->addDrawable(mesh);
  addPoints(mesh, Vector3f(-20.f, -1.f, -1.f), Vector3f(20.f, 1.f, 1.f));

  GeometryVisitor visitor;
  root.accept(visitor);

  const float radius = visitor.radius();
  const Vector3f center = visitor.center();
  // The bounding sphere must enclose the mesh corners and the atom position.
  EXPECT_GE(radius + 1e-4f, (Vector3f(-20.f, -1.f, -1.f) - center).norm());
  EXPECT_GE(radius + 1e-4f, (Vector3f(20.f, 1.f, 1.f) - center).norm());
  EXPECT_GE(radius + 1e-4f, center.norm());
  // And be larger than the sphere set alone (radius 0).
  EXPECT_GT(radius, 19.f);
}

TEST(GeometryVisitorTest, emptyMeshChangesNothing)
{
  GroupNode root;
  auto* geometry = new GeometryNode;
  root.addChild(geometry);
  auto* spheres = new SphereGeometry;
  spheres->addSphere(Vector3f(1.f, 2.f, 3.f), Vector3ub(255, 0, 0), 1.f);
  spheres->addSphere(Vector3f(3.f, 2.f, 3.f), Vector3ub(255, 0, 0), 1.f);
  geometry->addDrawable(spheres);

  GeometryVisitor before;
  root.accept(before);
  const Vector3f center = before.center();
  const float radius = before.radius();

  geometry->addDrawable(new MeshGeometry);

  GeometryVisitor after;
  root.accept(after);
  EXPECT_EQ(center, after.center());
  EXPECT_EQ(radius, after.radius());

  // A mesh-only scene with an empty mesh stays empty.
  GeometryNode emptyRoot;
  emptyRoot.addDrawable(new MeshGeometry);
  GeometryVisitor empty;
  emptyRoot.accept(empty);
  EXPECT_EQ(Vector3f::Zero(), empty.center());
  EXPECT_EQ(0.f, empty.radius());
}

TEST(GeometryVisitorTest, overlay2DMeshIgnored)
{
  // The selection tool draws its rubber band as a 2D overlay mesh in screen
  // pixels; it must not stretch the scene bounds.
  GeometryNode root;
  auto* spheres = new SphereGeometry;
  spheres->addSphere(Vector3f(1.f, 2.f, 3.f), Vector3ub(255, 0, 0), 1.f);
  spheres->addSphere(Vector3f(3.f, 2.f, 3.f), Vector3ub(255, 0, 0), 1.f);
  root.addDrawable(spheres);

  GeometryVisitor before;
  root.accept(before);

  auto* overlay = new MeshGeometry;
  overlay->setRenderPass(Avogadro::Rendering::Overlay2DPass);
  root.addDrawable(overlay);
  addPoints(overlay, Vector3f(0.f, 0.f, 0.f), Vector3f(1500.f, 900.f, 0.f));

  GeometryVisitor after;
  root.accept(after);
  EXPECT_EQ(before.center(), after.center());
  EXPECT_EQ(before.radius(), after.radius());
}

TEST(GeometryVisitorTest, meshBoundsMaintenance)
{
  MeshGeometry mesh;
  Vector3f lo, hi;
  EXPECT_FALSE(mesh.bounds(lo, hi));

  // All three addVertices overloads must update the box.
  Array<Vector3f> v, n;
  v.push_back(Vector3f(-1.f, -2.f, -3.f));
  n.push_back(Vector3f::UnitZ());
  mesh.addVertices(v, n);
  Array<Vector3ub> c3;
  c3.push_back(Vector3ub(1, 2, 3));
  Array<Vector3f> v2(1, Vector3f(5.f, 0.f, 0.f));
  mesh.addVertices(v2, n, c3);
  Array<Avogadro::Vector4ub> c4;
  c4.push_back(Avogadro::Vector4ub(1, 2, 3, 4));
  Array<Vector3f> v3(1, Vector3f(0.f, 7.f, 9.f));
  mesh.addVertices(v3, n, c4);

  ASSERT_TRUE(mesh.bounds(lo, hi));
  EXPECT_EQ(Vector3f(-1.f, -2.f, -3.f), lo);
  EXPECT_EQ(Vector3f(5.f, 7.f, 9.f), hi);

  // Non-finite vertices are ignored.
  Array<Vector3f> bad(
    1, Vector3f(std::numeric_limits<float>::quiet_NaN(), 1000.f, 0.f));
  mesh.addVertices(bad, n);
  ASSERT_TRUE(mesh.bounds(lo, hi));
  EXPECT_EQ(Vector3f(5.f, 7.f, 9.f), hi);

  // Copies and swaps carry the box.
  MeshGeometry copy(mesh);
  ASSERT_TRUE(copy.bounds(lo, hi));
  EXPECT_EQ(Vector3f(5.f, 7.f, 9.f), hi);
  MeshGeometry other;
  swap(other, mesh);
  EXPECT_FALSE(mesh.bounds(lo, hi));
  ASSERT_TRUE(other.bounds(lo, hi));
  EXPECT_EQ(Vector3f(-1.f, -2.f, -3.f), lo);

  // clear() resets it.
  other.clear();
  EXPECT_FALSE(other.bounds(lo, hi));
  addPoints(&other, Vector3f(100.f, 100.f, 100.f),
            Vector3f(101.f, 101.f, 101.f));
  ASSERT_TRUE(other.bounds(lo, hi));
  EXPECT_EQ(Vector3f(100.f, 100.f, 100.f), lo);
}
