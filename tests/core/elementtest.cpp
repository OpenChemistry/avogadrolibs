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

#include <avogadro/core/elements.h>

using Avogadro::Core::Elements;

TEST(ElementTest, symbolSingles)
{
  EXPECT_EQ(Elements::atomicNumberFromSymbol("H"), 1);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("C"), 6);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("S"), 16);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("U"), 92);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("X"), Elements::InvalidElement);
}

TEST(ElementTest, symbolDoubles)
{
  EXPECT_EQ(Elements::atomicNumberFromSymbol("He"), 2);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("Fe"), 26);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("Uuh"), 116);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("Xe"), 54);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("Xeee"), Elements::InvalidElement);
}

TEST(ElementTest, names)
{
  EXPECT_STREQ(Elements::name(1), "Hydrogen");
  EXPECT_STREQ(Elements::name(6), "Carbon");
  EXPECT_STREQ(Elements::name(Elements::atomicNumberFromSymbol("Fe")), "Iron");
}

TEST(ElementTest, masses)
{
  EXPECT_EQ(Elements::mass(1), 1.00794);
  EXPECT_EQ(Elements::mass(6), 12.0107);
}

TEST(ElementTest, radiusVDW)
{
  EXPECT_EQ(Elements::radiusVDW(1), 1.2);
  EXPECT_EQ(Elements::radiusVDW(6), 1.7);
}

TEST(ElementTest, radiusCovalent)
{
  EXPECT_EQ(Elements::radiusCovalent(1), 0.37);
  EXPECT_EQ(Elements::radiusCovalent(6), 0.77);
}

TEST(ElementTest, colors)
{
  EXPECT_EQ(Elements::color(1)[0], 255);
  EXPECT_EQ(Elements::color(1)[1], 255);
  EXPECT_EQ(Elements::color(1)[2], 255);
  EXPECT_EQ(Elements::color(5)[0], 255);
  EXPECT_EQ(Elements::color(5)[1], 181);
  EXPECT_EQ(Elements::color(5)[2], 181);
  EXPECT_EQ(Elements::color(6)[0], 127);
  EXPECT_EQ(Elements::color(6)[1], 127);
  EXPECT_EQ(Elements::color(6)[2], 127);
}

TEST(ElementTest, dummyElement)
{
  EXPECT_EQ(Elements::radiusVDW(0), 0.69);
  EXPECT_EQ(Elements::radiusCovalent(0), 0.18);
}
