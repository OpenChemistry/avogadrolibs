/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/rendering/camera.h>

#include <Eigen/Geometry>

#include <iostream>

using Avogadro::Rendering::Camera;
using Avogadro::Vector3f;

void setUpOrthographic(Camera &camera)
{
  camera.calculateOrthographic(0, 10, 0, 10, 0, 1);
}

TEST(CameraTest, perspective)
{
  Camera camera;
  camera.calculatePerspective(40, 1.5, 1, 10);

  // Load in a known value for the result of this matrix.
  Eigen::Matrix4f expected;
  expected << 1.83165, 0.0, 0.0, 0.0,
              0.0, 2.74748, 0.0, 0.0,
              0.0, 0.0, -1.22222, -2.22222,
              0.0, 0.0, -1.0, 0.0;
  EXPECT_TRUE(camera.projection().matrix().isApprox(expected));
  // If it is incorrect, lets print out the result.
  if (!camera.projection().matrix().isApprox(expected)) {
    std::cout << "Error: No match\n" << camera.projection().matrix()
              << "\nexpected\n" << expected << std::endl;
  }
}

TEST(CameraTest, orthographic)
{
  Camera camera;
  camera.calculateOrthographic(0, 10, 0, 10, 0, 1);

  // Load in a known value for the result of this matrix.
  Eigen::Matrix4f expected;
  expected << 0.2, 0.0, 0.0,-1.0,
              0.0, 0.2, 0.0,-1.0,
              0.0, 0.0,-2.0,-1.0,
              0.0, 0.0, 0.0, 1.0;
  EXPECT_TRUE(camera.projection().matrix().isApprox(expected));
  // If it is incorrect, lets print out the result.
  if (!camera.projection().matrix().isApprox(expected)) {
    std::cout << "Error: No match\n" << camera.projection().matrix()
              << "\nexpected\n" << expected << std::endl;
  }
}

TEST(CameraTest, projectOrthographic)
{
  Camera camera;
  camera.calculateOrthographic(0, 10, 0, 10, 0, 1);
  camera.setViewport(100, 100);

  Vector3f position = camera.project(Vector3f(1.0, 2.0, 0.0));
  Vector3f expected(10.0, 20.0, 0.0);
  EXPECT_TRUE(position.isApprox(expected));
  if (!position.isApprox(expected)) {
    std::cout << "Error: No match\n" << position << std::endl;
  }
}

TEST(CameraTest, projectPerspective)
{
  Camera camera;
  camera.calculatePerspective(40, 1.5, 1, 10);
  camera.preTranslate(Vector3f(0, 0, -10));
  camera.setViewport(100, 100);

  Vector3f position = camera.project(Vector3f(1.0, 2.0, 0.0));
  Vector3f expected(59.1583, 77.4748, 1.0);
  EXPECT_TRUE(position.isApprox(expected));
  if (!position.isApprox(expected)) {
    std::cout << "Error: No match\n" << position << std::endl;
  }
}

TEST(CameraTest, unProjectOrthographic)
{
  Camera camera;
  camera.calculateOrthographic(0, 10, 0, 10, 0, 1);
  camera.setViewport(100, 100);

  Vector3f position = camera.unProject(Vector3f(10, 25, 0));
  Vector3f expected(1.0, 7.5, 0.0);
  EXPECT_TRUE(position.isApprox(expected));
  if (!position.isApprox(expected)) {
    std::cout << "Error: No match\n" << position << std::endl;
  }
}

TEST(CameraTest, unProjectPerspective)
{
  Camera camera;
  camera.calculatePerspective(40, 1.5, 1, 10);
  camera.preTranslate(Vector3f(0, 0, -10));
  camera.setViewport(100, 100);

  Vector3f position = camera.unProject(Vector3f(10, 25, 0));
  Vector3f expected(-0.436764, 0.181985, 9.0);
  EXPECT_TRUE(position.isApprox(expected));
  if (!position.isApprox(expected)) {
    std::cout << "Error: No match\n" << position << std::endl;
  }
}
