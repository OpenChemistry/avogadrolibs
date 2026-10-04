/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/meshgeometry.h>
#include <avogadro/rendering/plyvisitor.h>
#include <avogadro/rendering/spheregeometry.h>

#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::Core::Array;
using Avogadro::Rendering::Camera;
using Avogadro::Rendering::CylinderGeometry;
using Avogadro::Rendering::MeshGeometry;
using Avogadro::Rendering::PLYVisitor;
using Avogadro::Rendering::SphereGeometry;

TEST(PLYVisitorTest, headerMatchesBody)
{
  SphereGeometry spheres;
  spheres.addSphere(Vector3f(0, 0, 0), Vector3ub(255, 0, 0), 1.0f);
  spheres.addSphere(Vector3f(3, 0, 0), Vector3ub(0, 255, 0), 1.0f);
  CylinderGeometry cylinders;
  cylinders.addCylinder(Vector3f(0, 0, 0), Vector3f(3, 0, 0), 0.2f,
                        Vector3ub(255, 0, 0), Vector3ub(0, 255, 0));

  // An indexed mesh with shared vertices, to check index offsets.
  Array<Vector3f> vertices, normals;
  vertices.push_back(Vector3f(0, 0, 0));
  vertices.push_back(Vector3f(1, 0, 0));
  vertices.push_back(Vector3f(1, 1, 0));
  vertices.push_back(Vector3f(0, 1, 0));
  for (int i = 0; i < 4; ++i)
    normals.push_back(Vector3f(0, 0, 1));
  MeshGeometry mesh;
  mesh.addVertices(vertices, normals);
  mesh.addTriangle(0, 1, 2);
  mesh.addTriangle(0, 2, 3);

  Camera camera;
  PLYVisitor visitor(camera);
  visitor.setBinary(false);
  visitor.setSphereSubdivisions(3);
  visitor.begin();
  spheres.accept(visitor);
  cylinders.accept(visitor);
  mesh.accept(visitor);
  const std::string ply = visitor.end();

  std::istringstream in(ply);
  std::string line;
  size_t vertexCount = 0, faceCount = 0;
  bool sawNormals = false;
  ASSERT_TRUE(std::getline(in, line));
  EXPECT_EQ(line, "ply");
  while (std::getline(in, line) && line != "end_header") {
    if (line.rfind("element vertex ", 0) == 0)
      vertexCount = std::stoul(line.substr(15));
    else if (line.rfind("element face ", 0) == 0)
      faceCount = std::stoul(line.substr(13));
    else if (line == "property float nz")
      sawNormals = true;
  }
  ASSERT_EQ(line, "end_header");
  EXPECT_TRUE(sawNormals);
  EXPECT_GT(vertexCount, static_cast<size_t>(0));
  EXPECT_GT(faceCount, static_cast<size_t>(0));

  size_t vertexLines = 0, faceLines = 0;
  while (std::getline(in, line)) {
    if (line.empty())
      continue;
    std::istringstream fields(line);
    if (vertexLines < vertexCount) {
      float values[10];
      for (float& value : values)
        ASSERT_TRUE(static_cast<bool>(fields >> value)) << line;
      ++vertexLines;
    } else {
      unsigned int count, a, b, c;
      ASSERT_TRUE(static_cast<bool>(fields >> count >> a >> b >> c)) << line;
      EXPECT_EQ(count, 3u);
      EXPECT_LT(a, vertexCount);
      EXPECT_LT(b, vertexCount);
      EXPECT_LT(c, vertexCount);
      ++faceLines;
    }
  }
  EXPECT_EQ(vertexLines, vertexCount);
  EXPECT_EQ(faceLines, faceCount);

  // 2 spheres * (642 vertices, 1280 faces); the mesh adds 4 and 2.
  EXPECT_GE(vertexCount, static_cast<size_t>(2 * 642 + 4));
  EXPECT_GE(faceCount, static_cast<size_t>(2 * 1280 + 2));
}

TEST(PLYVisitorTest, emptyScene)
{
  Camera camera;
  PLYVisitor visitor(camera);
  visitor.begin();
  const std::string ply = visitor.end();
  EXPECT_NE(ply.find("element vertex 0\n"), std::string::npos);
  EXPECT_NE(ply.find("element face 0\n"), std::string::npos);
}

namespace {
std::uint32_t readU32(const std::string& data, size_t pos)
{
  std::uint32_t value = 0;
  for (int i = 3; i >= 0; --i)
    value = (value << 8) | static_cast<unsigned char>(data[pos + i]);
  return value;
}

float readF32(const std::string& data, size_t pos)
{
  std::uint32_t bits = readU32(data, pos);
  float value;
  std::memcpy(&value, &bits, 4);
  return value;
}
} // namespace

TEST(PLYVisitorTest, binaryLayout)
{
  Array<Vector3f> vertices, normals;
  Array<Vector4ub> colors;
  vertices.push_back(Vector3f(0.5f, -2.0f, 3.25f));
  vertices.push_back(Vector3f(1, 0, 0));
  vertices.push_back(Vector3f(1, 1, 0));
  vertices.push_back(Vector3f(0, 1, 0));
  normals.push_back(Vector3f(0, 0.5f, -1));
  for (int i = 1; i < 4; ++i)
    normals.push_back(Vector3f(0, 0, 1));
  for (int i = 0; i < 4; ++i)
    colors.push_back(Vector4ub(10 + i, 200, 255, 128));
  MeshGeometry mesh;
  mesh.addVertices(vertices, normals, colors);
  mesh.addTriangle(0, 1, 2);
  mesh.addTriangle(0, 2, 3);
  SphereGeometry spheres;
  spheres.addSphere(Vector3f(0, 0, 0), Vector3ub(1, 2, 3), 1.0f);

  Camera camera;
  PLYVisitor visitor(camera);
  EXPECT_TRUE(visitor.binary());
  visitor.setSphereSubdivisions(3);
  visitor.begin();
  mesh.accept(visitor);
  spheres.accept(visitor);

  std::ostringstream stream;
  ASSERT_TRUE(visitor.write(stream));
  const std::string data = stream.str();
  EXPECT_EQ(data, visitor.end());

  const std::string marker = "end_header\n";
  const size_t headerEnd = data.find(marker);
  ASSERT_NE(headerEnd, std::string::npos);
  const size_t body = headerEnd + marker.size();
  const std::string header = data.substr(0, headerEnd);
  EXPECT_NE(header.find("format binary_little_endian 1.0"), std::string::npos);
  EXPECT_NE(header.find("property list uchar uint vertex_indices"),
            std::string::npos);

  const size_t n = 4 + 642;
  const size_t m = 2 + 1280;
  EXPECT_NE(header.find("element vertex " + std::to_string(n)),
            std::string::npos);
  EXPECT_NE(header.find("element face " + std::to_string(m)),
            std::string::npos);
  ASSERT_EQ(data.size(), body + n * 28 + m * 13);

  // First vertex: the mesh vertex 0.
  EXPECT_EQ(readF32(data, body + 0), 0.5f);
  EXPECT_EQ(readF32(data, body + 4), -2.0f);
  EXPECT_EQ(readF32(data, body + 8), 3.25f);
  EXPECT_EQ(readF32(data, body + 12), 0.0f);
  EXPECT_EQ(readF32(data, body + 16), 0.5f);
  EXPECT_EQ(readF32(data, body + 20), -1.0f);
  EXPECT_EQ(static_cast<unsigned char>(data[body + 24]), 10);
  EXPECT_EQ(static_cast<unsigned char>(data[body + 25]), 200);
  EXPECT_EQ(static_cast<unsigned char>(data[body + 26]), 255);
  EXPECT_EQ(static_cast<unsigned char>(data[body + 27]), 128);
  // Vertex 2 of the mesh.
  EXPECT_EQ(readF32(data, body + 2 * 28), 1.0f);
  EXPECT_EQ(readF32(data, body + 2 * 28 + 4), 1.0f);

  // Faces: the mesh triangles, then the sphere's, offset by 4.
  const size_t faces = body + n * 28;
  EXPECT_EQ(static_cast<unsigned char>(data[faces]), 3);
  EXPECT_EQ(readU32(data, faces + 1), 0u);
  EXPECT_EQ(readU32(data, faces + 5), 1u);
  EXPECT_EQ(readU32(data, faces + 9), 2u);
  EXPECT_EQ(readU32(data, faces + 13 + 1), 0u);
  EXPECT_EQ(readU32(data, faces + 13 + 5), 2u);
  EXPECT_EQ(readU32(data, faces + 13 + 9), 3u);
  for (size_t f = 2; f < m; ++f) {
    const size_t pos = faces + f * 13;
    EXPECT_EQ(static_cast<unsigned char>(data[pos]), 3);
    for (int k = 0; k < 3; ++k) {
      std::uint32_t index = readU32(data, pos + 1 + 4 * k);
      EXPECT_GE(index, 4u);
      EXPECT_LT(index, n);
    }
  }
}

namespace {
// A mesh with known positions and normals, exported with a transform.
std::string exportQuad(PLYVisitor& visitor, bool binary)
{
  Array<Vector3f> vertices, normals;
  vertices.push_back(Vector3f(100, 200, 300));
  vertices.push_back(Vector3f(101, 200, 300));
  vertices.push_back(Vector3f(101, 201.5f, 300));
  vertices.push_back(Vector3f(100, 201.5f, 302));
  normals.push_back(Vector3f(0, 0, 1));
  normals.push_back(Vector3f(0, 1, 0));
  normals.push_back(Vector3f(1, 0, 0));
  normals.push_back(Vector3f(0, 0.6f, 0.8f));
  MeshGeometry mesh;
  mesh.addVertices(vertices, normals);
  mesh.addTriangle(0, 1, 2);
  mesh.addTriangle(0, 2, 3);
  visitor.setBinary(binary);
  visitor.begin();
  mesh.accept(visitor);
  return visitor.end();
}
} // namespace

TEST(PLYVisitorTest, defaultTransformIsIdentity)
{
  Camera camera;
  PLYVisitor visitor(camera);
  EXPECT_EQ(visitor.scale(), 1.0f);
  EXPECT_EQ(visitor.center(), Vector3f::Zero());
  const std::string data = exportQuad(visitor, true);
  const size_t body = data.find("end_header\n") + 11;
  EXPECT_EQ(readF32(data, body), 100.0f);
  EXPECT_EQ(readF32(data, body + 4), 200.0f);
  EXPECT_EQ(readF32(data, body + 8), 300.0f);
  EXPECT_EQ(readF32(data, body + 3 * 28 + 8), 302.0f);
}

TEST(PLYVisitorTest, centerAndScaleBinary)
{
  Camera camera;
  PLYVisitor visitor(camera);
  const Vector3f center(100.5f, 200.75f, 301);
  visitor.setCenter(center);
  visitor.setScale(0.1f);
  const std::string data = exportQuad(visitor, true);

  const std::string marker = "end_header\n";
  const size_t headerEnd = data.find(marker);
  ASSERT_NE(headerEnd, std::string::npos);
  const std::string header = data.substr(0, headerEnd);
  EXPECT_NE(header.find("comment generated by Avogadro\n"), std::string::npos);
  EXPECT_NE(header.find("comment Avogadro export: center 100.5 200.75 301 "
                        "angstrom, scale 0.100000001"),
            std::string::npos);
  // Comments follow "format" and precede the first element.
  EXPECT_LT(header.find("format "), header.find("comment "));
  EXPECT_LT(header.find("comment "), header.find("element "));

  const size_t body = headerEnd + marker.size();
  ASSERT_EQ(data.size(), body + 4 * 28 + 2 * 13);
  const Vector3f positions[] = { Vector3f(100, 200, 300),
                                 Vector3f(101, 200, 300),
                                 Vector3f(101, 201.5f, 300),
                                 Vector3f(100, 201.5f, 302) };
  const Vector3f normals[] = { Vector3f(0, 0, 1), Vector3f(0, 1, 0),
                               Vector3f(1, 0, 0), Vector3f(0, 0.6f, 0.8f) };
  for (int v = 0; v < 4; ++v) {
    const Vector3f expected = (positions[v] - center) * 0.1f;
    for (int k = 0; k < 3; ++k) {
      EXPECT_FLOAT_EQ(readF32(data, body + v * 28 + 4 * k), expected[k]);
      EXPECT_EQ(readF32(data, body + v * 28 + 12 + 4 * k), normals[v][k]);
    }
  }
  // Scale and centre do not change the face data.
  const size_t faces = body + 4 * 28;
  EXPECT_EQ(readU32(data, faces + 1), 0u);
  EXPECT_EQ(readU32(data, faces + 13 + 9), 3u);
}

TEST(PLYVisitorTest, centerAndScaleAscii)
{
  Camera camera;
  PLYVisitor visitor(camera);
  visitor.setCenter(Vector3f(100, 200, 300));
  visitor.setScale(2.0f);
  const std::string ply = exportQuad(visitor, false);
  const size_t body = ply.find("end_header\n") + 11;
  std::istringstream in(ply.substr(body));
  float values[10];
  for (float& value : values)
    ASSERT_TRUE(static_cast<bool>(in >> value));
  EXPECT_FLOAT_EQ(values[0], 0.0f);
  EXPECT_FLOAT_EQ(values[1], 0.0f);
  EXPECT_FLOAT_EQ(values[2], 0.0f);
  EXPECT_FLOAT_EQ(values[5], 1.0f); // normal untouched
  for (float& value : values)
    ASSERT_TRUE(static_cast<bool>(in >> value)); // second vertex
  EXPECT_FLOAT_EQ(values[0], 2.0f);
  EXPECT_FLOAT_EQ(values[4], 1.0f);
}

TEST(PLYVisitorTest, badScaleIgnored)
{
  Camera camera;
  PLYVisitor visitor(camera);
  visitor.setScale(0.5f);
  visitor.setScale(0.0f);
  visitor.setScale(-1.0f);
  visitor.setScale(std::nanf(""));
  visitor.setScale(INFINITY);
  EXPECT_EQ(visitor.scale(), 0.5f);
}

TEST(PLYVisitorTest, bounds)
{
  Camera camera;
  PLYVisitor visitor(camera);
  Vector3f lo(7, 7, 7), hi(7, 7, 7);
  EXPECT_FALSE(visitor.bounds(lo, hi));
  EXPECT_EQ(lo, Vector3f(7, 7, 7)); // untouched

  exportQuad(visitor, true);
  ASSERT_TRUE(visitor.bounds(lo, hi));
  EXPECT_EQ(lo, Vector3f(100, 200, 300));
  EXPECT_EQ(hi, Vector3f(101, 201.5f, 302));
}
