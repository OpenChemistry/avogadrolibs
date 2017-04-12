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

#include <avogadro/rendering/absolutequadstrategy.h>
#include <avogadro/rendering/camera.h>

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

typedef Avogadro::Rendering::AbsoluteQuadStrategy Strategy;

using Avogadro::Core::Array;
using Avogadro::Rendering::Camera;
using Avogadro::Vector2f;
using Avogadro::Vector3f;

TEST(AbsoluteQuadStrategyTest, exercise)
{
  Strategy s;

  Vector2f dims(501.2f, 612.5f);
  s.setDimensions(dims);
  EXPECT_EQ(dims, s.dimensions());

  Strategy::HAlign hAlign(Strategy::HRight);
  s.setHAlign(hAlign);
  EXPECT_EQ(hAlign, s.hAlign());

  Strategy::VAlign vAlign(Strategy::VBottom);
  s.setVAlign(vAlign);
  EXPECT_EQ(vAlign, s.vAlign());

  Vector3f normal(Vector3f(3.f, 4.f, 5.f).normalized());
  s.setNormal(normal);
  EXPECT_EQ(normal, s.normal());

  Vector3f up(Vector3f(1.f, 5.f, 7.f).normalized());
  s.setUp(up);
  EXPECT_EQ(up, s.up());

  Vector3f anchor(9.3f, 2.1f, -1.8f);
  s.setAnchor(anchor);
  EXPECT_EQ(anchor, s.anchor());

  Camera camera; // dummy, doesn't affect resulting quad.
  Array<Vector3f> quad(s.quad(camera));

  ASSERT_EQ(4, quad.size());

  EXPECT_FLOAT_EQ(-460.86874f, quad[0][0]);
  EXPECT_FLOAT_EQ(-326.70682f, quad[0][1]);
  EXPECT_FLOAT_EQ(543.34692f, quad[0][2]);

  EXPECT_FLOAT_EQ(-537.40002f, quad[1][0]);
  EXPECT_FLOAT_EQ(81.459717f, quad[1][1]);
  EXPECT_FLOAT_EQ(262.73242f, quad[1][2]);

  EXPECT_FLOAT_EQ(85.831268f, quad[2][0]);
  EXPECT_FLOAT_EQ(-406.06653f, quad[2][1]);
  EXPECT_FLOAT_EQ(278.81454f, quad[2][2]);

  EXPECT_FLOAT_EQ(9.2999878f, quad[3][0]);
  EXPECT_FLOAT_EQ(2.1000061f, quad[3][1]);
  EXPECT_FLOAT_EQ(-1.7999573f, quad[3][2]);
}
