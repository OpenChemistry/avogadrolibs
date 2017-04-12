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

#include <avogadro/rendering/absoluteoverlayquadstrategy.h>
#include <avogadro/rendering/camera.h>

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

typedef Avogadro::Rendering::AbsoluteOverlayQuadStrategy Strategy;

using Avogadro::Core::Array;
using Avogadro::Rendering::Camera;
using Avogadro::Vector2f;
using Avogadro::Vector3f;
using Avogadro::Vector2i;

TEST(AbsoluteOverlayQuadStrategyTest, exercise)
{
  Strategy s;

  Vector2i anchor(15, 25);
  s.setAnchor(anchor);
  EXPECT_EQ(anchor, s.anchor());

  Vector2f dims(50.f, 61.f);
  s.setDimensions(dims);
  EXPECT_EQ(dims, s.dimensions());

  Strategy::HAlign hAlign(Strategy::HLeft);
  Strategy::VAlign vAlign(Strategy::VBottom);
  s.setAlign(hAlign, vAlign);
  EXPECT_EQ(hAlign, s.hAlign());
  EXPECT_EQ(vAlign, s.vAlign());

  Camera camera; // Configure for overlay:
  camera.setIdentity();
  camera.setViewport(400, 400);
  camera.calculateOrthographic(0.f, 400.f, 0.f, 400.f, -1.f, 1.f);
  Array<Vector3f> quad(s.quad(camera));

  ASSERT_EQ(4, quad.size());

  EXPECT_FLOAT_EQ(15, quad[0][0]);
  EXPECT_FLOAT_EQ(86, quad[0][1]);
  EXPECT_FLOAT_EQ(0, quad[0][2]);

  EXPECT_FLOAT_EQ(65, quad[1][0]);
  EXPECT_FLOAT_EQ(86, quad[1][1]);
  EXPECT_FLOAT_EQ(0, quad[1][2]);

  EXPECT_FLOAT_EQ(15, quad[2][0]);
  EXPECT_FLOAT_EQ(25, quad[2][1]);
  EXPECT_FLOAT_EQ(0, quad[2][2]);

  EXPECT_FLOAT_EQ(65, quad[3][0]);
  EXPECT_FLOAT_EQ(25, quad[3][1]);
  EXPECT_FLOAT_EQ(0, quad[3][2]);
}
