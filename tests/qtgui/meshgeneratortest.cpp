/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/mesh.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/meshgenerator.h>

#include <QtCore/QThreadPool>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <vector>

using Avogadro::Matrix3;
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

// A non-trivial field: overlapping Gaussian blobs on an odd-sized grid, cut
// off at the cube faces, so the isosurface crosses every slab boundary and the
// x/y/z "end" cells.
void fillBlobs(Cube& cube)
{
  struct Blob
  {
    double x, y, z, width, amplitude;
  };
  const Blob blobs[] = { { -1.1, -0.4, 0.3, 1.0, 0.9 },
                         { 0.9, 0.7, -0.5, 0.8, 1.2 },
                         { 0.1, -1.3, 1.0, 1.1, 0.7 },
                         { 1.2, -0.9, 0.9, 0.6, 1.0 },
                         { -0.3, 1.1, 1.2, 0.9, 0.8 } };
  const Vector3i dim = cube.dimensions();
  for (int i = 0; i < dim.x(); ++i)
    for (int j = 0; j < dim.y(); ++j)
      for (int k = 0; k < dim.z(); ++k) {
        const Vector3 pos =
          cube.position(i * dim.y() * dim.z() + j * dim.z() + k);
        double value = 0.0;
        for (const Blob& b : blobs) {
          const double r2 = (pos - Vector3(b.x, b.y, b.z)).squaredNorm();
          value += b.amplitude * std::exp(-r2 / (b.width * b.width));
        }
        cube.setValue(i, j, k, static_cast<float>(value));
      }
}

std::uint64_t hashArray(const Avogadro::Core::Array<Avogadro::Vector3f>& a,
                        std::uint64_t h)
{
  for (size_t n = 0; n < a.size(); ++n) {
    unsigned char bytes[sizeof(float) * 3];
    std::memcpy(bytes, a[n].data(), sizeof(bytes));
    for (unsigned char c : bytes)
      h = (h ^ c) * 1099511628211ull;
  }
  return h;
}

std::uint64_t hashMesh(const Mesh& mesh)
{
  std::uint64_t h = 14695981039346656037ull;
  h = hashArray(mesh.vertices(), h);
  h = hashArray(mesh.normals(), h);
  return hashArray(mesh.triangles(), h);
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

// Regression test: the convenience constructor dropped its reverse argument.
TEST(MeshGeneratorTest, constructorHonorsReverse)
{
  Cube cube;
  ASSERT_TRUE(cube.setLimits(Vector3(-2.0, -2.0, -2.0), Vector3i(16, 16, 16),
                             Vector3(0.25, 0.25, 0.25)));
  Vector3i dim = cube.dimensions();
  for (int i = 0; i < dim.x(); ++i)
    for (int j = 0; j < dim.y(); ++j)
      for (int k = 0; k < dim.z(); ++k) {
        Vector3 pos = cube.position(i * dim.y() * dim.z() + j * dim.z() + k);
        cube.setValue(i, j, k, static_cast<float>(pos.norm()) - 1.2f);
      }

  Mesh viaCtor, viaInit;
  MeshGenerator ctorGen(&cube, &viaCtor, 0.0f, 0, true);
  MeshGenerator initGen;
  ASSERT_TRUE(initGen.initialize(&cube, &viaInit, 0.0f, 0, true));
  ctorGen.run();
  initGen.run();

  ASSERT_GT(viaInit.triangles().size(), static_cast<size_t>(0));
  ASSERT_EQ(viaCtor.triangles().size(), viaInit.triangles().size());
  ASSERT_EQ(viaCtor.normals().size(), viaInit.normals().size());
  for (size_t t = 0; t < viaInit.triangles().size(); ++t)
    EXPECT_EQ(viaCtor.triangles()[t], viaInit.triangles()[t]);
  for (size_t v = 0; v < viaInit.normals().size(); ++v)
    EXPECT_TRUE(viaCtor.normals()[v].isApprox(viaInit.normals()[v]));
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

// The Flying Edges passes run in parallel over z slabs. The result must not
// depend on how many threads the pool has, nor vary from run to run.
TEST(MeshGeneratorTest, parallelMatchesSingleThread)
{
  Cube cube;
  ASSERT_TRUE(cube.setLimits(Vector3(-1.8, -2.0, -1.4), Vector3i(37, 41, 29),
                             Vector3(0.1, 0.1, 0.1)));
  fillBlobs(cube);

  QThreadPool* pool = QThreadPool::globalInstance();
  const int savedThreads = pool->maxThreadCount();

  for (bool reverse : { false, true }) {
    for (int passes : { 0, 1 }) {
      Mesh reference;
      pool->setMaxThreadCount(1);
      MeshGenerator serial;
      ASSERT_TRUE(serial.initialize(&cube, &reference, 0.6f, passes, reverse));
      serial.run();
      pool->setMaxThreadCount(std::max(4, savedThreads));

      ASSERT_GT(reference.triangles().size(), static_cast<size_t>(100));
      const std::uint64_t expected = hashMesh(reference);

      for (int repeat = 0; repeat < 5; ++repeat) {
        Mesh mesh;
        MeshGenerator gen;
        ASSERT_TRUE(gen.initialize(&cube, &mesh, 0.6f, passes, reverse));
        gen.run();
        ASSERT_EQ(mesh.vertices().size(), reference.vertices().size());
        ASSERT_EQ(mesh.normals().size(), reference.normals().size());
        ASSERT_EQ(mesh.triangles().size(), reference.triangles().size());
        EXPECT_EQ(hashMesh(mesh), expected)
          << "reverse=" << reverse << " passes=" << passes;
        EXPECT_TRUE(std::equal(mesh.vertices().begin(), mesh.vertices().end(),
                               reference.vertices().begin()));
        EXPECT_TRUE(std::equal(mesh.normals().begin(), mesh.normals().end(),
                               reference.normals().begin()));
        EXPECT_TRUE(std::equal(mesh.triangles().begin(), mesh.triangles().end(),
                               reference.triangles().begin()));
      }
    }
  }
  pool->setMaxThreadCount(savedThreads);
}

namespace {

// Samples f = |x - center| on a grid with the given steps that is centered on
// the point, and extracts the isosurface at radius.
void checkSphereOnGrid(const Matrix3& steps, int smoothingPasses)
{
  const Vector3 center(0.3, -0.2, 0.1);
  const double radius = 1.2;
  const Vector3i dim(22, 22, 22);
  const Vector3 half = 0.5 * Vector3(dim.x() - 1, dim.y() - 1, dim.z() - 1);

  Cube cube;
  ASSERT_TRUE(cube.setStepLimits(center - steps * half, dim, steps));
  for (unsigned int i = 0; i < cube.data()->size(); ++i)
    cube.setValue(i, static_cast<float>((cube.position(i) - center).norm()));

  Mesh mesh;
  MeshGenerator gen;
  ASSERT_TRUE(
    gen.initialize(&cube, &mesh, static_cast<float>(radius), smoothingPasses));
  gen.run();
  ASSERT_GT(mesh.vertices().size(), static_cast<size_t>(100));
  ASSERT_EQ(mesh.vertices().size(), mesh.normals().size());

  const double shortest =
    std::min({ steps.col(0).norm(), steps.col(1).norm(), steps.col(2).norm() });
  double meanRadial = 0.0;
  double worstRadial = 1.0;
  for (size_t v = 0; v < mesh.vertices().size(); ++v) {
    const Vector3 r = mesh.vertices()[v].cast<double>() - center;
    // The surface is where it should be (smoothing shrinks it a little).
    const double tolerance = (smoothingPasses > 0 ? 0.3 : 0.1) * shortest;
    EXPECT_NEAR(r.norm(), radius, tolerance + 0.05 * shortest);
    const Vector3 n = mesh.normals()[v].cast<double>();
    ASSERT_GT(n.norm(), 0.0);
    // The normals point away from the center, f growing outward.
    const double radial = n.normalized().dot(r.normalized());
    meanRadial += radial;
    worstRadial = std::min(worstRadial, radial);
  }
  meanRadial /= static_cast<double>(mesh.vertices().size());
  EXPECT_GT(meanRadial, 0.95) << "passes " << smoothingPasses;
  EXPECT_GT(worstRadial, 0.5) << "passes " << smoothingPasses;
}

Matrix3 skewedMeshSteps()
{
  Matrix3 steps;
  steps << 0.26, 0.08, -0.05, //
    0.02, 0.24, 0.06,         //
    -0.03, 0.04, 0.25;
  return steps;
}

} // namespace

TEST(MeshGeneratorTest, skewedGridSphere)
{
  const Matrix3 steps = skewedMeshSteps();
  ASSERT_GT(steps.determinant(), 0.0);
  for (int passes : { 0, 1 })
    checkSphereOnGrid(steps, passes);
}

// A step matrix with a negative determinant mirrors the grid, which must not
// turn the surface inside out.
TEST(MeshGeneratorTest, leftHandedGridSphere)
{
  Matrix3 steps = skewedMeshSteps();
  steps.col(1) *= -1.0;
  ASSERT_LT(steps.determinant(), 0.0);
  for (int passes : { 0, 1 })
    checkSphereOnGrid(steps, passes);

  // An axis-aligned grid with a backwards axis, too.
  Matrix3 diagonal = Matrix3::Zero();
  diagonal.diagonal() = Vector3(-0.25, 0.25, 0.25);
  for (int passes : { 0, 1 })
    checkSphereOnGrid(diagonal, passes);
}
