/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/vector.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/scene.h>

#include <cmath>
#include <vector>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Rendering::ColorNormalVertex;
using Avogadro::Rendering::CylinderGeometry;
using Avogadro::Rendering::Identifier;

namespace {

constexpr unsigned int resolution = 8;

// The tessellation as it was written before the closed-form radials: one
// iterated AngleAxisf rotation per cylinder.
void referenceTessellate(
  const std::vector<Avogadro::Rendering::CylinderColor>& cyls,
  std::vector<ColorNormalVertex>& vertices, std::vector<unsigned int>& indices)
{
  const float step =
    2.0f * static_cast<float>(M_PI) / static_cast<float>(resolution);
  for (const auto& c : cyls) {
    const Vector3f direction = (c.end2 - c.end1).normalized();
    Vector3f radialVec = direction.unitOrthogonal() * c.radius;
    Eigen::AngleAxisf transform(step, direction);
    std::vector<Vector3f> radials;
    for (unsigned int j = 0; j < resolution; ++j) {
      radials.push_back(radialVec);
      radialVec = transform * radialVec;
    }
    ColorNormalVertex vert(c.color, -direction, c.end1);
    ColorNormalVertex vert2(c.color2, -direction, c.end1);
    const auto start = static_cast<unsigned int>(vertices.size());
    for (auto& radial : radials) {
      vert.normal = radial;
      vert.vertex = c.end1 + radial;
      vertices.push_back(vert);
      vert2.normal = vert.normal;
      vert2.vertex = c.end2 + radial;
      vertices.push_back(vert2);
    }
    for (unsigned int j = 0; j < resolution; ++j) {
      unsigned int r1 = j + j;
      unsigned int r2 = (j != 0 ? r1 : resolution + resolution) - 2;
      indices.push_back(start + r1);
      indices.push_back(start + r1 + 1);
      indices.push_back(start + r2);
      indices.push_back(start + r2);
      indices.push_back(start + r1 + 1);
      indices.push_back(start + r2 + 1);
    }
  }
}

} // namespace

TEST(CylinderGeometryTest, tessellateMatchesIteratedRotation)
{
  CylinderGeometry geometry;
  const Vector3ub red(255, 0, 0), blue(0, 0, 255), green(0, 255, 0);
  // axis aligned, both signs
  geometry.addCylinder(Vector3f(0, 0, 0), Vector3f(1, 0, 0), 0.1f, red, blue);
  geometry.addCylinder(Vector3f(0, 0, 0), Vector3f(0, -2, 0), 0.2f, green);
  geometry.addCylinder(Vector3f(1, 1, 1), Vector3f(1, 1, 4), 0.3f, blue, red);
  // arbitrary directions
  geometry.addCylinder(Vector3f(0.5f, -1, 2), Vector3f(3, 4.5f, -1), 0.15f, red,
                       green);
  geometry.addCylinder(Vector3f(-3, 2, 1), Vector3f(-1, -5, 7), 0.25f, green);
  // nearly antiparallel to the axis unitOrthogonal() prefers, both signs
  geometry.addCylinder(Vector3f(0, 0, 0), Vector3f(1e-4f, 1e-4f, -1), 0.2f, red,
                       blue);
  geometry.addCylinder(Vector3f(0, 0, 0), Vector3f(-1e-4f, 2e-4f, 1), 0.2f,
                       blue, red);
  // tiny and large radii, short and long axes
  geometry.addCylinder(Vector3f(0, 0, 0), Vector3f(1, 2, 3), 1e-4f, red, blue);
  geometry.addCylinder(Vector3f(10, 10, 10), Vector3f(12, 9, 11), 50.0f, green,
                       red);
  geometry.addCylinder(Vector3f(0, 0, 0), Vector3f(100, -80, 60), 0.5f, blue);
  geometry.addCylinder(Vector3f(0, 0, 0), Vector3f(0.01f, 0.02f, 0.01f), 0.05f,
                       red, green);

  std::vector<ColorNormalVertex> vertices, refVertices;
  std::vector<unsigned int> indices, refIndices;
  geometry.tessellate(vertices, indices);
  referenceTessellate(geometry.cylinders(), refVertices, refIndices);

  const size_t n = geometry.size();
  ASSERT_EQ(vertices.size(), n * 2 * resolution);
  ASSERT_EQ(indices.size(), n * 6 * resolution);
  ASSERT_EQ(refVertices.size(), vertices.size());
  EXPECT_EQ(indices, refIndices);

  for (size_t c = 0; c < n; ++c) {
    const float radius = geometry.cylinders()[c].radius;
    const float tol = 1e-5f * radius;
    // Positions are end + radial, so allow the absolute size of the end
    // point in single precision on top of the relative-to-radius tolerance.
    const float posTol =
      tol + 1e-6f * std::max(geometry.cylinders()[c].end1.norm(),
                             geometry.cylinders()[c].end2.norm());
    for (size_t k = 0; k < 2 * resolution; ++k) {
      const auto& v = vertices[c * 2 * resolution + k];
      const auto& r = refVertices[c * 2 * resolution + k];
      ASSERT_TRUE(v.vertex.allFinite()) << "cylinder " << c;
      EXPECT_LE((v.normal - r.normal).norm(), tol)
        << "cylinder " << c << " vertex " << k;
      EXPECT_LE((v.vertex - r.vertex).norm(), posTol)
        << "cylinder " << c << " vertex " << k;
      EXPECT_EQ(v.color, r.color);
      // radials are perpendicular to the axis and have the cylinder radius
      EXPECT_NEAR(v.normal.norm(), radius, tol);
    }
  }
}

TEST(CylinderGeometryTest, tessellateClearsOutputs)
{
  CylinderGeometry geometry;
  std::vector<ColorNormalVertex> vertices(5);
  std::vector<unsigned int> indices(7, 3);
  geometry.tessellate(vertices, indices);
  EXPECT_TRUE(vertices.empty());
  EXPECT_TRUE(indices.empty());

  geometry.addCylinder(Vector3f(0, 0, 0), Vector3f(0, 0, 1), 1.0f,
                       Vector3ub(1, 2, 3));
  geometry.tessellate(vertices, indices);
  EXPECT_EQ(vertices.size(), 2 * resolution);
  EXPECT_EQ(indices.size(), 6 * resolution);
}

// The explicit-index map used to be a std::map; a cylinder with no explicit
// index fell off the end of find() whenever any other cylinder had one.
TEST(CylinderGeometryTest, hitsUseExplicitIndexWhenPresent)
{
  CylinderGeometry geometry;
  geometry.identifier().molecule = &geometry; // any non-null address
  geometry.identifier().type = Avogadro::Rendering::BondType;
  const Vector3ub c(10, 20, 30);
  // Three parallel cylinders along x at y = 0, 10, 20.
  geometry.addCylinder(Vector3f(0, 0, 0), Vector3f(1, 0, 0), 0.5f, c, 42);
  geometry.addCylinder(Vector3f(0, 10, 0), Vector3f(1, 10, 0), 0.5f, c); // none
  geometry.addCylinder(Vector3f(0, 20, 0), Vector3f(1, 20, 0), 0.5f, c, c, 7);
  geometry.addCylinder(Vector3f(0, 30, 0), Vector3f(1, 30, 0), 0.5f, c); // none

  const float ys[] = { 0.0f, 10.0f, 20.0f, 30.0f };
  const size_t expected[] = { 42, 1, 7, 3 };
  for (int i = 0; i < 4; ++i) {
    auto hits = geometry.hits(Vector3f(0.5f, ys[i], -5),
                              Vector3f(0.5f, ys[i], 5), Vector3f(0, 0, 1));
    ASSERT_EQ(hits.size(), 1u) << i;
    EXPECT_EQ(hits.begin()->second.index, expected[i]) << i;
  }

  // No explicit indices at all: identified by position.
  CylinderGeometry plain;
  plain.identifier().molecule = &plain;
  plain.identifier().type = Avogadro::Rendering::BondType;
  plain.addCylinder(Vector3f(0, 0, 0), Vector3f(1, 0, 0), 0.5f, c);
  plain.addCylinder(Vector3f(0, 10, 0), Vector3f(1, 10, 0), 0.5f, c);
  auto hits = plain.hits(Vector3f(0.5f, 10, -5), Vector3f(0.5f, 10, 5),
                         Vector3f(0, 0, 1));
  ASSERT_EQ(hits.size(), 1u);
  EXPECT_EQ(hits.begin()->second.index, 1u);

  // Copies and clear() keep the mapping consistent.
  CylinderGeometry copy(geometry);
  hits =
    copy.hits(Vector3f(0.5f, 0, -5), Vector3f(0.5f, 0, 5), Vector3f(0, 0, 1));
  ASSERT_EQ(hits.size(), 1u);
  EXPECT_EQ(hits.begin()->second.index, 42u);
  copy.clear();
  copy.addCylinder(Vector3f(0, 0, 0), Vector3f(1, 0, 0), 0.5f, c);
  hits =
    copy.hits(Vector3f(0.5f, 0, -5), Vector3f(0.5f, 0, 5), Vector3f(0, 0, 1));
  ASSERT_EQ(hits.size(), 1u);
  EXPECT_EQ(hits.begin()->second.index, 0u);
}
