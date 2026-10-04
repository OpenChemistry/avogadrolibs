/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/vector.h>
#include <avogadro/rendering/bsplinegeometry.h>
#include <avogadro/rendering/cartoongeometry.h>

#include <cmath>
#include <vector>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Core::Residue;
using Avogadro::Rendering::BSplineGeometry;
using Avogadro::Rendering::Cartoon;
using Avogadro::Rendering::ColorNormalVertex;

namespace {

void addHelix(Cartoon& cartoon, int count, size_t group = 0)
{
  for (int i = 0; i < count; ++i) {
    float t = static_cast<float>(i) * 100.0f * 3.14159265f / 180.0f;
    auto structure = i < count / 2 ? Residue::SecondaryStructure::alphaHelix
                                   : Residue::SecondaryStructure::coil;
    cartoon.addPoint(Vector3f(2.3f * std::cos(t), 2.3f * std::sin(t), 1.5f * i),
                     Vector3ub(10 + i, 20 + i, 30 + i), group,
                     static_cast<size_t>(i), structure);
  }
}

bool allFinite(const std::vector<ColorNormalVertex>& vertices)
{
  for (const auto& v : vertices) {
    for (int k = 0; k < 3; ++k) {
      if (!std::isfinite(v.vertex[k]) || !std::isfinite(v.normal[k]))
        return false;
    }
  }
  return true;
}

} // namespace

TEST(CurveGeometryTest, cartoonHelix)
{
  Cartoon cartoon(0.1f, 0.5f);
  addHelix(cartoon, 30);

  std::vector<ColorNormalVertex> vertices;
  std::vector<unsigned int> indices;
  cartoon.tessellate(0, vertices, indices);

  ASSERT_FALSE(vertices.empty());
  ASSERT_FALSE(indices.empty());
  EXPECT_EQ(indices.size() % 3, static_cast<size_t>(0));
  for (unsigned int index : indices)
    EXPECT_LT(index, vertices.size());
  EXPECT_TRUE(allFinite(vertices));
  EXPECT_FALSE(cartoon.isFlatLine(0));
  // Normals are directions scaled by the local tube size, never zero.
  for (const auto& v : vertices)
    EXPECT_GT(v.normal.norm(), 0.0f);
}

TEST(CurveGeometryTest, tessellateIsRepeatable)
{
  Cartoon cartoon(0.1f, 0.5f);
  addHelix(cartoon, 30);

  std::vector<ColorNormalVertex> v1, v2;
  std::vector<unsigned int> i1, i2;
  cartoon.tessellate(0, v1, i1);
  // Outputs are cleared, not appended to.
  cartoon.tessellate(0, v2, i2);
  cartoon.tessellate(0, v2, i2);
  EXPECT_EQ(v1.size(), v2.size());
  EXPECT_EQ(i1, i2);
}

TEST(CurveGeometryTest, shortAndDegenerateInput)
{
  std::vector<ColorNormalVertex> vertices;
  std::vector<unsigned int> indices;

  // No lines at all: out of range is harmless.
  Cartoon empty(0.1f, 0.5f);
  empty.tessellate(0, vertices, indices);
  EXPECT_TRUE(vertices.empty());
  EXPECT_TRUE(indices.empty());

  for (int count = 1; count <= 5; ++count) {
    Cartoon cartoon(0.1f, 0.5f);
    for (int i = 0; i < count; ++i)
      cartoon.addPoint(Vector3f(3.8f * i, 0.0f, 0.0f), Vector3ub(1, 2, 3), 0,
                       static_cast<size_t>(i),
                       Residue::SecondaryStructure::coil);
    cartoon.tessellate(0, vertices, indices);
    EXPECT_TRUE(allFinite(vertices)) << count << " points";
    for (unsigned int index : indices)
      EXPECT_LT(index, vertices.size());
  }

  // Too few points to build a spline: nothing, but no crash either.
  Cartoon two(0.1f, 0.5f);
  two.addPoint(Vector3f(0, 0, 0), Vector3ub(1, 2, 3), 0, 0,
               Residue::SecondaryStructure::coil);
  two.addPoint(Vector3f(1, 0, 0), Vector3ub(1, 2, 3), 0, 1,
               Residue::SecondaryStructure::coil);
  two.tessellate(0, vertices, indices);
  EXPECT_TRUE(vertices.empty());
  EXPECT_TRUE(indices.empty());
}

TEST(CurveGeometryTest, coincidentPoints)
{
  Cartoon cartoon(0.1f, 0.5f);
  for (int i = 0; i < 20; ++i)
    cartoon.addPoint(Vector3f(1.0f, 2.0f, 3.0f), Vector3ub(1, 2, 3), 0,
                     static_cast<size_t>(i), Residue::SecondaryStructure::coil);

  std::vector<ColorNormalVertex> vertices;
  std::vector<unsigned int> indices;
  cartoon.tessellate(0, vertices, indices);
  EXPECT_TRUE(allFinite(vertices));
  for (unsigned int index : indices)
    EXPECT_LT(index, vertices.size());
}

TEST(CurveGeometryTest, flatLineHasNoIndices)
{
  // A negative radius is a line width in pixels: drawn as a line strip.
  BSplineGeometry spline(true);
  for (int i = 0; i < 40; ++i)
    spline.addPoint(Vector3f(0.5f * i, std::sin(0.3f * i), 0.0f),
                    Vector3ub(255, 0, 0), -2.0f, 0, static_cast<size_t>(i));

  std::vector<ColorNormalVertex> vertices;
  std::vector<unsigned int> indices;
  spline.tessellate(0, vertices, indices);
  EXPECT_TRUE(spline.isFlatLine(0));
  EXPECT_FALSE(vertices.empty());
  EXPECT_TRUE(indices.empty());
  EXPECT_TRUE(allFinite(vertices));

  // A positive radius is a real tube.
  BSplineGeometry tube(true);
  for (int i = 0; i < 40; ++i)
    tube.addPoint(Vector3f(0.5f * i, std::sin(0.3f * i), 0.0f),
                  Vector3ub(255, 0, 0), 0.2f, 0, static_cast<size_t>(i));
  tube.tessellate(0, vertices, indices);
  EXPECT_FALSE(tube.isFlatLine(0));
  EXPECT_FALSE(indices.empty());
  for (unsigned int index : indices)
    EXPECT_LT(index, vertices.size());
}
