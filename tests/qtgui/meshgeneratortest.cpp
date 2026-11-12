/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/mesh.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/meshgenerator.h>

#include <cmath>

using Avogadro::Vector3;
using Avogadro::Vector3i;
using Avogadro::Core::Cube;
using Avogadro::Core::Mesh;
using Avogadro::QtGui::MeshGenerator;

namespace {

// Create a cube filled with distance-from-origin values
// Isosurface at value=r gives a sphere of radius r
void fillSphereFunction(Cube& cube)
{
  Vector3i dim = cube.dimensions();
  for (int i = 0; i < dim.x(); ++i)
    for (int j = 0; j < dim.y(); ++j)
      for (int k = 0; k < dim.z(); ++k) {
        unsigned int idx = i * dim.y() * dim.z() + j * dim.z() + k;
        Vector3 pos = cube.position(idx);
        float val = static_cast<float>(pos.norm());
        cube.setValue(i, j, k, val);
      }
}

} // namespace

TEST(MeshGeneratorTest, defaultConstructor)
{
  MeshGenerator gen;
  EXPECT_EQ(gen.cube(), nullptr);
  EXPECT_EQ(gen.mesh(), nullptr);
}

TEST(MeshGeneratorTest, initializeAndAccessors)
{
  Cube cube;
  cube.setLimits(Vector3(-3.0, -3.0, -3.0), Vector3(3.0, 3.0, 3.0),
                 Vector3i(8, 8, 8));
  fillSphereFunction(cube);

  Mesh mesh;
  MeshGenerator gen;
  bool ok = gen.initialize(&cube, &mesh, 1.5f);
  EXPECT_TRUE(ok);
  EXPECT_EQ(gen.cube(), &cube);
  EXPECT_EQ(gen.mesh(), &mesh);
}

TEST(MeshGeneratorTest, initializeNullCube)
{
  Mesh mesh;
  MeshGenerator gen;
  bool ok = gen.initialize(nullptr, &mesh, 1.0f);
  EXPECT_FALSE(ok);
}

TEST(MeshGeneratorTest, progressBounds)
{
  Cube cube;
  cube.setLimits(Vector3(-3.0, -3.0, -3.0), Vector3(3.0, 3.0, 3.0),
                 Vector3i(8, 8, 8));
  fillSphereFunction(cube);

  Mesh mesh;
  MeshGenerator gen;
  gen.initialize(&cube, &mesh, 1.5f);
  EXPECT_LT(gen.progressMinimum(), gen.progressMaximum());
}

TEST(MeshGeneratorTest, generateSphereMesh)
{
  // Create a cube with distance-from-origin values
  // Isosurface at 1.5 should produce a sphere mesh
  Cube cube;
  cube.setLimits(Vector3(-3.0, -3.0, -3.0), Vector3(3.0, 3.0, 3.0),
                 Vector3i(12, 12, 12));
  fillSphereFunction(cube);

  Mesh mesh;
  MeshGenerator gen;
  gen.initialize(&cube, &mesh, 1.5f);
  gen.run(); // synchronous execution

  // The mesh should have non-zero vertices and normals
  EXPECT_GT(mesh.vertices().size(), static_cast<size_t>(0));
  EXPECT_GT(mesh.normals().size(), static_cast<size_t>(0));
  // Vertices and normals should have the same count
  EXPECT_EQ(mesh.vertices().size(), mesh.normals().size());
}

// Regression test: initialize() sized its working arrays from
// dimension - 1 without checking, so a cube with fewer than two points on
// an axis gave zero or wrapped (huge) sizes.
TEST(MeshGeneratorTest, initializeRejectsThinCube)
{
  Mesh mesh;

  // An empty cube: all dimensions zero.
  Cube empty;
  MeshGenerator gen;
  EXPECT_FALSE(gen.initialize(&empty, &mesh, 1.0f));
  EXPECT_EQ(gen.cube(), nullptr);
  EXPECT_EQ(gen.mesh(), nullptr);

  // One point along each axis in turn -- valid for Cube, since the spacing
  // is given, but there are no cells to march.
  const Vector3i thin[] = { Vector3i(1, 4, 4), Vector3i(4, 1, 4),
                            Vector3i(4, 4, 1) };
  for (const auto& dim : thin) {
    Cube cube;
    ASSERT_TRUE(
      cube.setLimits(Vector3(0.0, 0.0, 0.0), dim, Vector3(0.5, 0.5, 0.5)));
    EXPECT_FALSE(gen.initialize(&cube, &mesh, 1.0f)) << dim.transpose();
    EXPECT_EQ(gen.cube(), nullptr);
  }

  // A rejected cube also drops a previously accepted one, so running the
  // generator afterwards does nothing rather than reusing stale pointers.
  Cube good;
  good.setLimits(Vector3(-3.0, -3.0, -3.0), Vector3(3.0, 3.0, 3.0),
                 Vector3i(8, 8, 8));
  fillSphereFunction(good);
  ASSERT_TRUE(gen.initialize(&good, &mesh, 1.5f));
  EXPECT_FALSE(gen.initialize(&empty, &mesh, 1.5f));
  EXPECT_EQ(gen.cube(), nullptr);
  gen.run();
  EXPECT_EQ(mesh.numVertices(), 0u);
}

// Regression test: the gradient-based normals used with 0 smoothing passes
// pointed opposite to the face-based normals of smoothed meshes.
TEST(MeshGeneratorTest, normalsAgreeAcrossSmoothingPasses)
{
  const Vector3 center(0.17, -0.23, 0.11);
  const float radius = 1.5f;

  for (bool negated : { false, true }) {
    Cube cube;
    ASSERT_TRUE(cube.setLimits(Vector3(-2.9, -3.1, -2.7), Vector3i(24, 24, 24),
                               Vector3(0.25, 0.26, 0.24)));
    Vector3i dim = cube.dimensions();
    for (int i = 0; i < dim.x(); ++i)
      for (int j = 0; j < dim.y(); ++j)
        for (int k = 0; k < dim.z(); ++k) {
          Vector3 pos = cube.position(i * dim.y() * dim.z() + j * dim.z() + k);
          float f = radius - static_cast<float>((pos - center).norm());
          cube.setValue(i, j, k, negated ? -f : f);
        }

    Mesh mesh0, mesh1;
    MeshGenerator gen0, gen1;
    ASSERT_TRUE(gen0.initialize(&cube, &mesh0, 0.0f, 0, negated));
    ASSERT_TRUE(gen1.initialize(&cube, &mesh1, 0.0f, 1, negated));
    gen0.run();
    gen1.run();

    ASSERT_GT(mesh0.vertices().size(), static_cast<size_t>(0));
    ASSERT_GT(mesh1.vertices().size(), static_cast<size_t>(0));

    // Compare against the radial direction for each mesh. Both must agree
    // on the sign (inward or outward), whichever it is.
    auto meanRadial = [&](const Mesh& m) {
      double sum = 0.0;
      for (size_t v = 0; v < m.vertices().size(); ++v) {
        Vector3 r = m.vertices()[v].cast<double>() - center;
        Vector3 n = m.normals()[v].cast<double>();
        if (r.norm() > 0.0 && n.norm() > 0.0)
          sum += n.normalized().dot(r.normalized());
      }
      return sum / static_cast<double>(m.vertices().size());
    };
    double d0 = meanRadial(mesh0);
    double d1 = meanRadial(mesh1);
    EXPECT_GT(std::abs(d0), 0.9) << "negated=" << negated;
    EXPECT_GT(std::abs(d1), 0.9) << "negated=" << negated;
    EXPECT_GT(d0 * d1, 0.0)
      << "negated=" << negated << " d0=" << d0 << " d1=" << d1;
    // The face normals point toward increasing |f| inside the lobe, i.e.
    // inward, for both the positive and the reversed negative lobe.
    EXPECT_LT(d0, -0.9) << "negated=" << negated;
    EXPECT_LT(d1, -0.9) << "negated=" << negated;
  }
}
