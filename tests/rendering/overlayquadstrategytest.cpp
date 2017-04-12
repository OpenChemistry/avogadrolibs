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

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/overlayquadstrategy.h>

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

typedef Avogadro::Rendering::OverlayQuadStrategy Strategy;

using Avogadro::Core::Array;
using Avogadro::Rendering::Camera;
using Avogadro::Vector2f;
using Avogadro::Vector3f;

TEST(OverlayQuadStrategyTest, exercise)
{
  Strategy s;

  Vector2f anchor(0.1f, 0.6f);
  s.setAnchor(anchor);
  EXPECT_EQ(anchor, s.anchor());

  Vector2f dims(50.f, 61.f);
  s.setDimensions(dims);
  EXPECT_EQ(dims, s.dimensions());

  Strategy::HAlign hAlign(Strategy::HLeft);
  s.setHAlign(hAlign);
  EXPECT_EQ(hAlign, s.hAlign());

  Strategy::VAlign vAlign(Strategy::VBottom);
  s.setVAlign(vAlign);
  EXPECT_EQ(vAlign, s.vAlign());

  Camera camera; // Configure for overlay:
  camera.setIdentity();
  camera.setViewport(400, 400);
  camera.calculateOrthographic(0.f, 400.f, 0.f, 400.f, -1.f, 1.f);
  Array<Vector3f> quad(s.quad(camera));

  ASSERT_EQ(4, quad.size());

  EXPECT_FLOAT_EQ(40, quad[0][0]);
  EXPECT_FLOAT_EQ(301, quad[0][1]);
  EXPECT_FLOAT_EQ(0, quad[0][2]);

  EXPECT_FLOAT_EQ(90, quad[1][0]);
  EXPECT_FLOAT_EQ(301, quad[1][1]);
  EXPECT_FLOAT_EQ(0, quad[1][2]);

  EXPECT_FLOAT_EQ(40, quad[2][0]);
  EXPECT_FLOAT_EQ(240, quad[2][1]);
  EXPECT_FLOAT_EQ(0, quad[2][2]);

  EXPECT_FLOAT_EQ(90, quad[3][0]);
  EXPECT_FLOAT_EQ(240, quad[3][1]);
  EXPECT_FLOAT_EQ(0, quad[3][2]);
}
