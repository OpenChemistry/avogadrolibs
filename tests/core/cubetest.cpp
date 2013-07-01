/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/cube.h>

using Avogadro::Core::Cube;
using Avogadro::Vector3;
using Avogadro::Vector3i;

TEST(CubeTest, initialize)
{
  Cube cube;
  EXPECT_EQ(cube.dimensions(), Vector3i::Zero());
}

TEST(CubeTest, name)
{
  Cube cube;
  cube.setName("test");
  EXPECT_EQ(cube.name(), "test");
}

TEST(CubeTest, limits)
{
  Cube cube;
  cube.setLimits(Vector3(0.0, 0.0, 0.0), Vector3(1.0, 1.0, 1.0),
                 Vector3i(10, 10, 10));
  EXPECT_EQ(cube.data()->size(), 1000);
  for (int i = 0; i < 3; ++i) {
    EXPECT_DOUBLE_EQ(cube.min()[i], 0.0);
    EXPECT_DOUBLE_EQ(cube.max()[i], 1.0);
    EXPECT_EQ(cube.dimensions()[i], 10);
  }

  Cube cube2;
  cube2.setLimits(cube);
  for (int i = 0; i < 3; ++i) {
    EXPECT_DOUBLE_EQ(cube2.min()[i], 0.0);
    EXPECT_DOUBLE_EQ(cube2.max()[i], 1.0);
    EXPECT_EQ(cube2.dimensions()[i], 10);
  }
  EXPECT_EQ(cube.data()->size(), 1000);
}

TEST(CubeTest, value)
{
  Cube cube;
  cube.setLimits(Vector3(0.0, 0.0, 0.0), Vector3(1.0, 1.0, 1.0),
                 Vector3i(10, 10, 10));
  cube.setValue(0, 0, 0, 5.0);
  cube.setValue(0, 0, 1, 50.0);

  EXPECT_DOUBLE_EQ(cube.value(0, 0, 0), 5.0);
  EXPECT_DOUBLE_EQ(cube.value(0, 0, 1), 50.0);
}

TEST(CubeTest, minmax)
{
  Cube cube;
  cube.setLimits(Vector3(0.0, 0.0, 0.0), Vector3(1.0, 1.0, 1.0),
                 Vector3i(10, 10, 10));
  cube.setValue(0, 0, 0, 5.0);
  cube.setValue(0, 0, 1, 50.0);

  EXPECT_DOUBLE_EQ(cube.minValue(), 0.0);
  EXPECT_DOUBLE_EQ(cube.maxValue(), 50.0);
}

TEST(CubeTest, index)
{
  Cube cube;
  cube.setLimits(Vector3(0.0, 0.0, 0.0), Vector3(1.0, 1.0, 1.0),
                 Vector3i(10, 10, 10));
  EXPECT_EQ(cube.closestIndex(Vector3(0.0, 0.0, 0.0)), 0);
  EXPECT_EQ(cube.closestIndex(Vector3(1.0, 0.0, 0.0)), 900);
  EXPECT_EQ(cube.closestIndex(Vector3(0.0, 1.0, 0.0)), 90);
  EXPECT_EQ(cube.closestIndex(Vector3(0.0, 0.0, 1.0)), 9);
  EXPECT_EQ(cube.closestIndex(Vector3(1.0, 1.0, 1.0)), 999);
}

TEST(CubeTest, position)
{
  Cube cube;
  cube.setLimits(Vector3(0.0, 0.0, 0.0), Vector3(1.0, 1.0, 1.0),
                 Vector3i(10, 10, 10));
  for (int i = 0; i < 3; ++i)
    EXPECT_DOUBLE_EQ(cube.position(0)[i], 0.0);
  for (int i = 0; i < 3; ++i)
    EXPECT_DOUBLE_EQ(cube.position(999)[i], 1.0);
}
