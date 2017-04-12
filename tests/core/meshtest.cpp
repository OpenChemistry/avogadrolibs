/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011-2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/color3f.h>
#include <avogadro/core/mesh.h>
#include <avogadro/core/vector.h>

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

TEST_F(MeshTest, assigment)
{
  Mesh assign = m_testMesh;

  assertEquals(m_testMesh, assign);
  EXPECT_NE(m_testMesh.lock(), assign.lock());
}
