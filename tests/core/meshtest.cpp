/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/color3f.h>
#include <avogadro/core/mesh.h>
#include <avogadro/core/vector.h>

#include <algorithm>
#include <vector>

using Avogadro::Vector3f;
using Avogadro::Core::Array;
using Avogadro::Core::Color3f;
using Avogadro::Core::Mesh;

class MeshTest : public testing::Test
{
public:
  MeshTest();
  void assertEquals(const Mesh& m1, const Mesh& m2);

protected:
  Mesh m_testMesh;
};

MeshTest::MeshTest()
{
  Array<Vector3f> vertices;
  Array<Vector3f> normals;
  Array<Color3f> colors;

  Color3f color = Color3f(23, 23, 23);
  colors.push_back(color);

  Vector3f vec(1.2f, 1.3f, 1.4f);

  vertices.push_back(vec);
  normals.push_back(vec);

  m_testMesh.setColors(colors);
  m_testMesh.setNormals(normals);
  m_testMesh.setVertices(vertices);
  m_testMesh.setIsoValue(1.2f);
  m_testMesh.setName("testmesh");
  m_testMesh.setOtherMesh(1);
}

void MeshTest::assertEquals(const Mesh& m1, const Mesh& m2)
{
  EXPECT_EQ(m1.otherMesh(), m2.otherMesh());
  EXPECT_EQ(m1.name(), m2.name());
  EXPECT_EQ(m1.isoValue(), m2.isoValue());
  EXPECT_TRUE(m1.vertices() == m2.vertices());

  const Array<Color3f> colors1 = m1.colors();
  const Array<Color3f> colors2 = m1.colors();

  EXPECT_EQ(colors1.size(), colors2.size());

  int i = 0;
  for (Array<Color3f>::const_iterator it = colors1.begin(),
                                      itEnd = colors1.end();
       it != itEnd; ++it) {
    EXPECT_EQ(it->red(), colors2[i].red());
    EXPECT_EQ(it->green(), colors2[i].green());
    EXPECT_EQ(it->blue(), colors2[i].blue());
    ++i;
  }
  EXPECT_TRUE(m1.normals() == m2.normals());
}

TEST_F(MeshTest, copy)
{
  Mesh copy(m_testMesh);

  assertEquals(m_testMesh, copy);
  EXPECT_NE(m_testMesh.lock(), copy.lock());
}

TEST_F(MeshTest, assignment)
{
  Mesh assign = m_testMesh;

  assertEquals(m_testMesh, assign);
  EXPECT_NE(m_testMesh.lock(), assign.lock());
}

TEST_F(MeshTest, smoothMatchesReference)
{
  // A perturbed grid with a couple of isolated vertices.
  const int n = 12;
  Array<Vector3f> vertices;
  Array<Vector3f> triangles;
  for (int y = 0; y < n; ++y) {
    for (int x = 0; x < n; ++x) {
      float jitter = static_cast<float>((x * 7 + y * 13) % 5) * 0.1f;
      vertices.push_back(
        Vector3f(static_cast<float>(x), static_cast<float>(y), jitter));
    }
  }
  vertices.push_back(Vector3f(50.0f, 50.0f, 50.0f)); // isolated
  for (int y = 0; y + 1 < n; ++y) {
    for (int x = 0; x + 1 < n; ++x) {
      float a = static_cast<float>(y * n + x);
      float b = a + 1.0f;
      float c = a + static_cast<float>(n);
      float d = c + 1.0f;
      triangles.push_back(Vector3f(a, b, c));
      triangles.push_back(Vector3f(b, d, c));
    }
  }
  Mesh mesh;
  mesh.setVertices(vertices);
  mesh.setNormals(Array<Vector3f>(vertices.size(), Vector3f::Zero()));
  mesh.setTriangles(triangles);

  // Reference: straightforward Jacobi smoothing, same operation order.
  std::vector<std::vector<size_t>> adj(vertices.size());
  for (const auto& t : triangles) {
    size_t i = static_cast<size_t>(t.x());
    size_t j = static_cast<size_t>(t.y());
    size_t k = static_cast<size_t>(t.z());
    adj[i].push_back(j);
    adj[i].push_back(k);
    adj[j].push_back(i);
    adj[j].push_back(k);
    adj[k].push_back(i);
    adj[k].push_back(j);
  }
  for (auto& v : adj) {
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
  }
  std::vector<Vector3f> ref(vertices.begin(), vertices.end());
  for (int iter = 0; iter < 3; ++iter) {
    std::vector<Vector3f> next = ref;
    for (size_t i = 0; i < ref.size(); ++i) {
      if (adj[i].empty())
        continue;
      Vector3f sum(0.0f, 0.0f, 0.0f);
      for (size_t nb : adj[i])
        sum += ref[nb];
      sum += 1.0f * ref[i];
      next[i] = sum / (1.0f + adj[i].size());
    }
    ref = next;
  }

  mesh.smooth(3);
  ASSERT_EQ(mesh.vertices().size(), ref.size());
  for (size_t i = 0; i < ref.size(); ++i) {
    EXPECT_EQ(mesh.vertices()[i].x(), ref[i].x());
    EXPECT_EQ(mesh.vertices()[i].y(), ref[i].y());
    EXPECT_EQ(mesh.vertices()[i].z(), ref[i].z());
  }
  EXPECT_EQ(mesh.vertices()[vertices.size() - 1].x(), 50.0f);
  EXPECT_EQ(mesh.normals().size(), ref.size());
}
