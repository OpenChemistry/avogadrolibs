/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>
#include <avogadro/rendering/arrowgeometry.h>
#include <avogadro/rendering/cartoongeometry.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/dashedlinegeometry.h>
#include <avogadro/rendering/linestripgeometry.h>
#include <avogadro/rendering/meshgeometry.h>
#include <avogadro/rendering/spheregeometry.h>
#include <avogadro/rendering/tessellatingvisitor.h>
#include <avogadro/rendering/widelinegeometry.h>

#include <cmath>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::Core::Array;
using Avogadro::Rendering::ArrowGeometry;
using Avogadro::Rendering::Cartoon;
using Avogadro::Rendering::CylinderGeometry;
using Avogadro::Rendering::DashedLineGeometry;
using Avogadro::Rendering::LineStripGeometry;
using Avogadro::Rendering::MeshGeometry;
using Avogadro::Rendering::SphereGeometry;
using Avogadro::Rendering::TessellatedMesh;
using Avogadro::Rendering::TessellatingVisitor;
using Avogadro::Rendering::WideLineGeometry;

namespace {

void expectWellFormed(const TessellatedMesh& mesh)
{
  EXPECT_EQ(mesh.positions.size(), mesh.normals.size());
  EXPECT_EQ(mesh.positions.size(), mesh.colors.size());
  EXPECT_EQ(mesh.indices.size() % 3, static_cast<size_t>(0));
  for (unsigned int index : mesh.indices)
    EXPECT_LT(index, mesh.positions.size());
  for (size_t i = 0; i < mesh.positions.size(); ++i) {
    for (int k = 0; k < 3; ++k) {
      EXPECT_TRUE(std::isfinite(mesh.positions[i][k]));
      EXPECT_TRUE(std::isfinite(mesh.normals[i][k]));
    }
  }
}

// Counter-clockwise triangles must face the same way as the vertex normals.
void expectOutwardWinding(const TessellatedMesh& mesh)
{
  for (size_t i = 0; i + 2 < mesh.indices.size(); i += 3) {
    const unsigned int a = mesh.indices[i];
    const unsigned int b = mesh.indices[i + 1];
    const unsigned int c = mesh.indices[i + 2];
    Vector3f face = (mesh.positions[b] - mesh.positions[a])
                      .cross(mesh.positions[c] - mesh.positions[a]);
    if (face.norm() < 1e-9f)
      continue; // degenerate sliver (e.g. a pole), no orientation
    Vector3f normal = mesh.normals[a] + mesh.normals[b] + mesh.normals[c];
    EXPECT_GT(face.dot(normal), 0.0f) << "triangle " << i / 3;
  }
}

} // namespace

TEST(TessellatingVisitorTest, sphereCounts)
{
  for (unsigned int level = 0; level <= 3; ++level) {
    SphereGeometry spheres;
    spheres.addSphere(Vector3f(1, 2, 3), Vector3ub(10, 20, 30), 1.5f);
    spheres.addSphere(Vector3f(-4, 0, 1), Vector3ub(40, 50, 60), 0.5f);

    TessellatingVisitor visitor;
    visitor.setSphereSubdivisions(level);
    spheres.accept(visitor);

    ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
    const auto& mesh = visitor.meshes()[0];
    EXPECT_EQ(mesh.name, "spheres");
    size_t scale = static_cast<size_t>(1) << (2 * level); // 4^level
    // Shared vertices: V = 10 * 4^n + 2, F = 20 * 4^n per sphere.
    EXPECT_EQ(mesh.positions.size(), 2 * (10 * scale + 2));
    EXPECT_EQ(mesh.indices.size(), 2 * 20 * scale * 3);
    expectWellFormed(mesh);
  }
}

TEST(TessellatingVisitorTest, sphereGeometry)
{
  SphereGeometry spheres;
  const Vector3f center(1, 2, 3);
  spheres.addSphere(center, Vector3ub(10, 20, 30), 1.5f);
  spheres.setOpacity(0.5f);

  TessellatingVisitor visitor;
  visitor.setSphereSubdivisions(3);
  spheres.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
  const auto& mesh = visitor.meshes()[0];
  EXPECT_EQ(mesh.positions.size(), static_cast<size_t>(642));

  for (size_t i = 0; i < mesh.positions.size(); ++i) {
    EXPECT_NEAR((mesh.positions[i] - center).norm(), 1.5f, 1e-4f);
    EXPECT_NEAR(mesh.normals[i].norm(), 1.0f, 1e-4f);
    EXPECT_EQ(mesh.colors[i], Vector4ub(10, 20, 30, 128));
  }
  expectOutwardWinding(mesh);
}

TEST(TessellatingVisitorTest, sphereCacheSurvivesLevelChange)
{
  SphereGeometry spheres;
  spheres.addSphere(Vector3f::Zero(), Vector3ub(1, 1, 1), 1.0f);

  TessellatingVisitor visitor;
  visitor.setSphereSubdivisions(3);
  spheres.accept(visitor);
  visitor.setSphereSubdivisions(1);
  spheres.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(2));
  EXPECT_EQ(visitor.meshes()[0].positions.size(), static_cast<size_t>(642));
  EXPECT_EQ(visitor.meshes()[1].positions.size(), static_cast<size_t>(42));

  visitor.clear();
  EXPECT_TRUE(visitor.meshes().empty());
}

TEST(TessellatingVisitorTest, twoColourCylinder)
{
  CylinderGeometry cylinders;
  const Vector3ub red(255, 0, 0), blue(0, 0, 255);
  cylinders.addCylinder(Vector3f(0, 0, 0), Vector3f(0, 0, 2), 0.5f, red, blue);

  TessellatingVisitor visitor;
  visitor.setCylinderSides(12);
  cylinders.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
  const auto& mesh = visitor.meshes()[0];
  EXPECT_EQ(mesh.name, "cylinders");
  expectWellFormed(mesh);
  expectOutwardWinding(mesh);

  // Vertices only exist at the two end planes (rings and caps): the end1
  // plane carries color, the end2 plane color2.
  size_t atEnd1 = 0, atEnd2 = 0;
  for (size_t i = 0; i < mesh.positions.size(); ++i) {
    const Vector3f& p = mesh.positions[i];
    EXPECT_LE(std::hypot(p[0], p[1]), 0.5f + 1e-5f);
    if (p[2] < 1.0f) {
      EXPECT_NEAR(p[2], 0.0f, 1e-6f);
      EXPECT_EQ(mesh.colors[i], Vector4ub(255, 0, 0, 255));
      ++atEnd1;
    } else {
      EXPECT_NEAR(p[2], 2.0f, 1e-6f);
      EXPECT_EQ(mesh.colors[i], Vector4ub(0, 0, 255, 255));
      ++atEnd2;
    }
  }
  EXPECT_EQ(atEnd1, atEnd2);
  EXPECT_GT(atEnd1, static_cast<size_t>(0));
}

TEST(TessellatingVisitorTest, cylinderAnyAxis)
{
  // Axes along and against each coordinate axis, and diagonal.
  const Vector3f axes[] = { Vector3f(1, 0, 0),  Vector3f(0, 1, 0),
                            Vector3f(0, 0, 1),  Vector3f(0, -1, 0),
                            Vector3f(0, 0, -1), Vector3f(1, 1, 1) };
  for (const auto& axis : axes) {
    CylinderGeometry cylinders;
    cylinders.addCylinder(Vector3f(1, 1, 1), Vector3f(1, 1, 1) + axis, 0.1f,
                          Vector3ub(1, 2, 3));
    TessellatingVisitor visitor;
    cylinders.accept(visitor);
    ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
    expectWellFormed(visitor.meshes()[0]);
    expectOutwardWinding(visitor.meshes()[0]);
  }
}

TEST(TessellatingVisitorTest, zeroLengthCylinderIsSkipped)
{
  CylinderGeometry cylinders;
  cylinders.addCylinder(Vector3f(1, 2, 3), Vector3f(1, 2, 3), 0.5f,
                        Vector3ub(1, 2, 3));
  TessellatingVisitor visitor;
  cylinders.accept(visitor);
  EXPECT_TRUE(visitor.meshes().empty());

  // A good cylinder next to a bad one is still exported, without NaNs.
  cylinders.addCylinder(Vector3f(0, 0, 0), Vector3f(0, 1, 0), 0.5f,
                        Vector3ub(1, 2, 3));
  cylinders.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
  expectWellFormed(visitor.meshes()[0]);
}

TEST(TessellatingVisitorTest, cylinderOpacity)
{
  CylinderGeometry cylinders;
  cylinders.addCylinder(Vector3f(0, 0, 0), Vector3f(0, 1, 0), 0.5f,
                        Vector3ub(9, 8, 7));
  cylinders.setOpacity(0.25f);
  TessellatingVisitor visitor;
  cylinders.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
  for (const auto& color : visitor.meshes()[0].colors)
    EXPECT_EQ(color[3], 64);
}

TEST(TessellatingVisitorTest, indexedMeshKeepsIndices)
{
  // A quad of four shared vertices and two triangles: a regression test for
  // exporters that assumed a triangle soup.
  Array<Vector3f> vertices, normals;
  Array<Vector4ub> colors;
  vertices.push_back(Vector3f(0, 0, 0));
  vertices.push_back(Vector3f(1, 0, 0));
  vertices.push_back(Vector3f(1, 1, 0));
  vertices.push_back(Vector3f(0, 1, 0));
  for (int i = 0; i < 4; ++i) {
    normals.push_back(Vector3f(0, 0, 1));
    colors.push_back(Vector4ub(10 * i, 20, 30, 100 + i));
  }

  MeshGeometry mesh;
  mesh.addVertices(vertices, normals, colors);
  mesh.addTriangle(0, 1, 2);
  mesh.addTriangle(0, 2, 3);

  TessellatingVisitor visitor;
  mesh.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
  const auto& result = visitor.meshes()[0];
  EXPECT_EQ(result.name, "mesh");
  ASSERT_EQ(result.positions.size(), static_cast<size_t>(4));
  const std::vector<unsigned int> expected = { 0, 1, 2, 0, 2, 3 };
  EXPECT_EQ(result.indices, expected);
  for (int i = 0; i < 4; ++i) {
    EXPECT_EQ(result.positions[i], vertices[i]);
    EXPECT_EQ(result.colors[i], colors[i]); // alpha is the vertex alpha
  }
}

TEST(TessellatingVisitorTest, meshOutOfRangeTrianglesDropped)
{
  Array<Vector3f> vertices, normals;
  for (int i = 0; i < 3; ++i) {
    vertices.push_back(Vector3f(i, 0, 0));
    normals.push_back(Vector3f(0, 0, 1));
  }
  MeshGeometry mesh;
  mesh.addVertices(vertices, normals);
  mesh.addTriangle(0, 1, 2);
  mesh.addTriangle(0, 1, 7);

  TessellatingVisitor visitor;
  mesh.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
  EXPECT_EQ(visitor.meshes()[0].indices.size(), static_cast<size_t>(3));
}

TEST(TessellatingVisitorTest, dashedLinesOneTubePerDash)
{
  DashedLineGeometry dashed;
  dashed.addDashedLine(Vector3f(0, 0, 0), Vector3f(4, 0, 0), 4);
  dashed.addDashedLine(Vector3f(0, 1, 0), Vector3f(0, 1, 6), 3);
  // 2 * dashCount points per line, consecutive pairs are dashes.
  EXPECT_EQ(dashed.vertices().size(), static_cast<size_t>(14));

  TessellatingVisitor visitor;
  dashed.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
  const auto& mesh = visitor.meshes()[0];
  EXPECT_EQ(mesh.name, "dashedlines");
  expectWellFormed(mesh);

  // Each dash: 2 rings of 8 plus two caps of 1 + 8 vertices; 16 side and 16
  // cap triangles.
  const size_t dashes = 7;
  EXPECT_EQ(mesh.positions.size(), dashes * 34);
  EXPECT_EQ(mesh.indices.size(), dashes * 32 * 3);
}

TEST(TessellatingVisitorTest, lineRadiusScalesTubes)
{
  DashedLineGeometry dashed;
  dashed.addDashedLine(Vector3f(0, 0, 0), Vector3f(0, 0, 4), 1);

  TessellatingVisitor visitor;
  visitor.setLineRadius(0.1f);
  dashed.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
  float maxRadius = 0.0f;
  for (const auto& p : visitor.meshes()[0].positions)
    maxRadius = std::max(maxRadius, std::hypot(p[0], p[1]));
  EXPECT_NEAR(maxRadius, 0.1f, 1e-5f); // the cap centres lie on the axis
}

TEST(TessellatingVisitorTest, arrow)
{
  ArrowGeometry arrows;
  arrows.addSingleArrow(Vector3f(0, 0, 0), Vector3f(0, 0, 10),
                        Vector3ub(0, 255, 0));

  TessellatingVisitor visitor;
  arrows.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
  const auto& mesh = visitor.meshes()[0];
  EXPECT_EQ(mesh.name, "arrows");
  expectWellFormed(mesh);
  expectOutwardWinding(mesh);

  float maxZ = -1e9f, minZ = 1e9f, maxRadius = 0.0f;
  for (const auto& p : mesh.positions) {
    maxZ = std::max(maxZ, p[2]);
    minZ = std::min(minZ, p[2]);
    maxRadius = std::max(maxRadius, std::hypot(p[0], p[1]));
  }
  EXPECT_NEAR(maxZ, 10.0f, 1e-4f);
  EXPECT_NEAR(minZ, 0.0f, 1e-4f);
  EXPECT_NEAR(maxRadius, 0.5f, 1e-4f); // cone base: 0.05 * length
}

TEST(TessellatingVisitorTest, lineStripsAndWideLines)
{
  LineStripGeometry strips;
  Array<Vector3f> points;
  points.push_back(Vector3f(0, 0, 0));
  points.push_back(Vector3f(1, 0, 0));
  points.push_back(Vector3f(1, 1, 0));
  strips.addLineStrip(points, Vector3ub(255, 255, 0), 1.0f);

  WideLineGeometry wide;
  wide.addLine(Vector3f(0, 0, 0), Vector3f(2, 0, 0), Vector3ub(1, 2, 3), 0.1f);
  wide.addDashedLine(Vector3f(0, 1, 0), Vector3f(3, 1, 0), Vector3ub(1, 2, 3),
                     0.1f, 3);

  TessellatingVisitor visitor;
  strips.accept(visitor);
  wide.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(2));
  for (const auto& mesh : visitor.meshes()) {
    EXPECT_EQ(mesh.name, "lines");
    expectWellFormed(mesh);
    EXPECT_FALSE(mesh.indices.empty());
  }
  // The wide line has a true width: radius = half the line width, and its
  // solid line is extended by that much at both ends.
  const auto& wideMesh = visitor.meshes()[1];
  float maxRadius = 0.0f;
  for (const auto& p : wideMesh.positions)
    maxRadius = std::max(maxRadius, std::hypot(p[1], p[2]));
  EXPECT_NEAR(maxRadius, 1.0f + 0.05f, 1e-4f); // dashed line at y = 1
}

TEST(TessellatingVisitorTest, cartoonCurves)
{
  Cartoon cartoon(0.1f, 0.5f);
  for (int i = 0; i < 30; ++i) {
    float t = static_cast<float>(i) * 1.7f;
    cartoon.addPoint(Vector3f(2.3f * std::cos(t), 2.3f * std::sin(t), 1.5f * i),
                     Vector3ub(10, 20, 30), 0, static_cast<size_t>(i),
                     Avogadro::Core::Residue::SecondaryStructure::alphaHelix);
  }

  TessellatingVisitor visitor;
  cartoon.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
  const auto& mesh = visitor.meshes()[0];
  EXPECT_EQ(mesh.name, "cartoon");
  expectWellFormed(mesh);
  for (size_t i = 0; i < mesh.normals.size(); ++i) {
    EXPECT_NEAR(mesh.normals[i].norm(), 1.0f, 1e-4f);
    EXPECT_EQ(mesh.colors[i][3], 255);
  }
}

namespace {
size_t sphereVertices(unsigned int level)
{
  return 10 * (static_cast<size_t>(1) << (2 * level)) + 2;
}
} // namespace

TEST(TessellatingVisitorTest, adaptiveSphereLevels)
{
  TessellatingVisitor visitor;
  // Edge angles shrink by about half per level.
  float previous = 10.0f;
  for (unsigned int level = 0; level <= 5; ++level) {
    float angle = visitor.sphereMaxEdgeAngle(level);
    EXPECT_LT(angle, previous);
    EXPECT_GT(angle, 0.0f);
    previous = angle;
  }
  EXPECT_NEAR(visitor.sphereMaxEdgeAngle(0), 1.1071487f, 1e-4f); // atan(2)

  EXPECT_EQ(visitor.sphereLevelForRadius(0.3f), 1u);
  EXPECT_EQ(visitor.sphereLevelForRadius(1.0f), 1u);
  EXPECT_EQ(visitor.sphereLevelForRadius(1.7f), 2u);
  EXPECT_EQ(visitor.sphereLevelForRadius(5.0f), 3u);
  EXPECT_EQ(visitor.sphereLevelForRadius(1000.0f), 5u); // clamped

  unsigned int last = 0;
  for (float r = 0.05f; r < 20.0f; r *= 1.1f) {
    unsigned int level = visitor.sphereLevelForRadius(r);
    EXPECT_GE(level, last) << r;
    last = level;
  }
}

TEST(TessellatingVisitorTest, adaptiveSpheresInOneDrawable)
{
  SphereGeometry spheres;
  const float radii[] = { 0.3f, 1.7f, 5.0f, 1.0f };
  const unsigned int levels[] = { 1, 2, 3, 1 };
  size_t expected = 0;
  for (int i = 0; i < 4; ++i) {
    spheres.addSphere(Vector3f(10.0f * i, 0, 0), Vector3ub(1, 2, 3), radii[i]);
    expected += sphereVertices(levels[i]);
  }

  TessellatingVisitor visitor;
  spheres.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
  const auto& mesh = visitor.meshes()[0];
  EXPECT_EQ(mesh.positions.size(), expected);
  expectWellFormed(mesh);
  expectOutwardWinding(mesh);

  size_t first = 0;
  for (int i = 0; i < 4; ++i) {
    for (size_t k = 0; k < sphereVertices(levels[i]); ++k) {
      const Vector3f center(10.0f * i, 0, 0);
      EXPECT_NEAR((mesh.positions[first + k] - center).norm(), radii[i],
                  1e-4f * radii[i]);
    }
    first += sphereVertices(levels[i]);
  }

  // Tolerance and range change the choice; fixed values override both.
  visitor.clear();
  visitor.setTessellationTolerance(0.5f);
  EXPECT_EQ(visitor.sphereLevelForRadius(1.7f), 1u);
  visitor.setSphereLevelRange(2, 3);
  EXPECT_EQ(visitor.sphereLevelForRadius(0.1f), 2u);
  EXPECT_EQ(visitor.sphereLevelForRadius(100.0f), 3u);
  visitor.setSphereSubdivisions(0);
  EXPECT_EQ(visitor.sphereLevelForRadius(100.0f), 0u);
  visitor.useAdaptiveSpheres();
  EXPECT_EQ(visitor.sphereLevelForRadius(100.0f), 3u);
}

TEST(TessellatingVisitorTest, badToleranceIgnored)
{
  TessellatingVisitor visitor;
  visitor.setTessellationTolerance(0.0f);
  visitor.setTessellationTolerance(-1.0f);
  visitor.setTessellationTolerance(std::nanf(""));
  visitor.setTessellationTolerance(INFINITY);
  EXPECT_EQ(visitor.tessellationTolerance(), 0.05f);
}

TEST(TessellatingVisitorTest, adaptiveCylinderSides)
{
  TessellatingVisitor visitor;
  EXPECT_EQ(visitor.cylinderSidesForRadius(0.1f), 8u);  // 3 -> minimum 8
  EXPECT_EQ(visitor.cylinderSidesForRadius(0.01f), 8u); // tolerance >= radius
  EXPECT_EQ(visitor.cylinderSidesForRadius(0.05f), 8u);
  EXPECT_EQ(visitor.cylinderSidesForRadius(1.0f), 10u);
  EXPECT_EQ(visitor.cylinderSidesForRadius(5.0f), 23u);
  EXPECT_EQ(visitor.cylinderSidesForRadius(1e6f), 48u); // capped
  unsigned int last = 0;
  for (float r = 0.01f; r < 50.0f; r *= 1.2f) {
    unsigned int n = visitor.cylinderSidesForRadius(r);
    EXPECT_GE(n, last);
    last = n;
  }

  // The exported cylinder uses it: 2 rings plus two caps (centre + ring).
  CylinderGeometry cylinders;
  cylinders.addCylinder(Vector3f(0, 0, 0), Vector3f(0, 0, 2), 1.0f,
                        Vector3ub(1, 2, 3));
  cylinders.accept(visitor);
  ASSERT_EQ(visitor.meshes().size(), static_cast<size_t>(1));
  EXPECT_EQ(visitor.meshes()[0].positions.size(), 2u * 10 + 2u * (1 + 10));

  visitor.setCylinderSides(6);
  EXPECT_EQ(visitor.cylinderSidesForRadius(5.0f), 6u);
  visitor.useAdaptiveCylinders();
  EXPECT_EQ(visitor.cylinderSidesForRadius(5.0f), 23u);
}
