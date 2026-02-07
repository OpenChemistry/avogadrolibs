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
