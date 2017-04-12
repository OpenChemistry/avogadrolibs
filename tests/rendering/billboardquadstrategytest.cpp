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

#include <avogadro/rendering/billboardquadstrategy.h>
#include <avogadro/rendering/camera.h>

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

typedef Avogadro::Rendering::BillboardQuadStrategy Strategy;

using Avogadro::Core::Array;
using Avogadro::Rendering::Camera;
using Avogadro::Vector2f;
using Avogadro::Vector3f;

TEST(BillboardQuadStrategyTest, exercise)
{
  Strategy s;

  Vector3f anchor(9.3f, 2.1f, -1.8f);
  s.setAnchor(anchor);
  EXPECT_EQ(anchor, s.anchor());

  float radius = 3.4f;
  s.setRadius(radius);
  EXPECT_EQ(radius, s.radius());

  bool useCameraUp = false;
  s.setUseCameraUp(useCameraUp);
  EXPECT_EQ(useCameraUp, s.useCameraUp());

  Vector3f up(Vector3f(1.f, 5.f, 7.f).normalized());
  s.setUp(up);
  EXPECT_EQ(up, s.up());

  Vector2f dims(501.2f, 612.5f);
  s.setDimensions(dims);
  EXPECT_EQ(dims, s.dimensions());

  Strategy::HAlign hAlign(Strategy::HRight);
  s.setHAlign(hAlign);
  EXPECT_EQ(hAlign, s.hAlign());

  Strategy::VAlign vAlign(Strategy::VBottom);
  s.setVAlign(vAlign);
  EXPECT_EQ(vAlign, s.vAlign());

  Camera camera;
  camera.setIdentity();
  camera.rotate(136.2f, Vector3f(205.f, 603.f, -141.f).normalized());
  camera.translate(Vector3f(-13.2f, 15.6f, 102.f));
  Array<Vector3f> quad(s.quad(camera));

  ASSERT_EQ(4, quad.size());

  EXPECT_FLOAT_EQ(243.83968f, quad[0][0]);
  EXPECT_FLOAT_EQ(-185.99776f, quad[0][1]);
  EXPECT_FLOAT_EQ(730.30627f, quad[0][2]);

  EXPECT_FLOAT_EQ(389.97992f, quad[1][0]);
  EXPECT_FLOAT_EQ(194.00380f, quad[1][1]);
  EXPECT_FLOAT_EQ(437.99942f, quad[1][2]);

  EXPECT_FLOAT_EQ(-134.35634f, quad[2][0]);
  EXPECT_FLOAT_EQ(-379.83984f, quad[2][1]);
  EXPECT_FLOAT_EQ(289.22885f, quad[2][2]);

  EXPECT_FLOAT_EQ(11.783905f, quad[3][0]);
  EXPECT_FLOAT_EQ(0.16171265f, quad[3][1]);
  EXPECT_FLOAT_EQ(-3.0780029f, quad[3][2]);

  // Test the useCameraUp options:
  useCameraUp = true;
  s.setUseCameraUp(useCameraUp);
  EXPECT_EQ(useCameraUp, s.useCameraUp());

  quad = s.quad(camera);

  ASSERT_EQ(4, quad.size());

  EXPECT_FLOAT_EQ(538.01459f, quad[0][0]);
  EXPECT_FLOAT_EQ(371.01038f, quad[0][1]);
  EXPECT_FLOAT_EQ(457.25916f, quad[0][2]);

  EXPECT_FLOAT_EQ(387.27307f, quad[1][0]);
  EXPECT_FLOAT_EQ(484.04947f, quad[1][1]);
  EXPECT_FLOAT_EQ(-7.1766663f, quad[1][2]);

  EXPECT_FLOAT_EQ(162.52542f, quad[2][0]);
  EXPECT_FLOAT_EQ(-112.87738f, quad[2][1]);
  EXPECT_FLOAT_EQ(461.35785f, quad[2][2]);

  EXPECT_FLOAT_EQ(11.783905f, quad[3][0]);
  EXPECT_FLOAT_EQ(0.16171265f, quad[3][1]);
  EXPECT_FLOAT_EQ(-3.0779662f, quad[3][2]);

  // Rotating the camera should update the quad:
  camera.preRotate(36.f, Vector3f::UnitY());

  quad = s.quad(camera);

  ASSERT_EQ(4, quad.size());

  EXPECT_FLOAT_EQ(727.31494f, quad[0][0]);
  EXPECT_FLOAT_EQ(218.08212f, quad[0][1]);
  EXPECT_FLOAT_EQ(-255.12888f, quad[0][2]);

  EXPECT_FLOAT_EQ(383.45709f, quad[1][0]);
  EXPECT_FLOAT_EQ(486.99631f, quad[1][1]);
  EXPECT_FLOAT_EQ(-8.8598633f, quad[1][2]);

  EXPECT_FLOAT_EQ(351.82578f, quad[2][0]);
  EXPECT_FLOAT_EQ(-265.80563f, quad[2][1]);
  EXPECT_FLOAT_EQ(-251.03018f, quad[2][2]);

  EXPECT_FLOAT_EQ(7.967926f, quad[3][0]);
  EXPECT_FLOAT_EQ(3.108551f, quad[3][1]);
  EXPECT_FLOAT_EQ(-4.7611632f, quad[3][2]);
}
