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
#include <avogadro/core/utilities.h>

using Avogadro::Core::Elements;

TEST(ElementTest, symbolSingles)
{
  EXPECT_EQ(Elements::atomicNumberFromSymbol("H"), 1);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("C"), 6);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("S"), 16);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("U"), 92);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("X"), Avogadro::InvalidElement);
}

TEST(ElementTest, symbolDoubles)
{
  EXPECT_EQ(Elements::atomicNumberFromSymbol("He"), 2);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("Fe"), 26);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("Lv"), 116);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("Xe"), 54);
  EXPECT_EQ(Elements::atomicNumberFromSymbol("Xeee"), Avogadro::InvalidElement);
}

TEST(ElementTest, names)
{
  EXPECT_STREQ(Elements::name(1), "Hydrogen");
  EXPECT_STREQ(Elements::name(6), "Carbon");
  EXPECT_STREQ(Elements::name(Elements::atomicNumberFromSymbol("Fe")), "Iron");
}

TEST(ElementTest, masses)
{
  EXPECT_EQ(Elements::mass(1), 1.00784);
  EXPECT_EQ(Elements::mass(6), 12.011);
}

TEST(ElementTest, radiusVDW)
{
  EXPECT_EQ(Elements::radiusVDW(1), 1.2);
  EXPECT_EQ(Elements::radiusVDW(6), 1.77);
}

TEST(ElementTest, radiusCovalent)
{
  EXPECT_EQ(Elements::radiusCovalent(1), 0.32);
  EXPECT_EQ(Elements::radiusCovalent(6), 0.75);
}

TEST(ElementTest, colors)
{
  // hydrogen
  EXPECT_EQ(Elements::color(1)[0], 240);
  EXPECT_EQ(Elements::color(1)[1], 240);
  EXPECT_EQ(Elements::color(1)[2], 240);

  // boron
  EXPECT_EQ(Elements::color(5)[0], 255);
  EXPECT_EQ(Elements::color(5)[1], 181);
  EXPECT_EQ(Elements::color(5)[2], 181);

  // carbon
  EXPECT_EQ(Elements::color(6)[0], 127);
  EXPECT_EQ(Elements::color(6)[1], 127);
  EXPECT_EQ(Elements::color(6)[2], 127);

  EXPECT_EQ(Elements::color(7)[0], 48);
  EXPECT_EQ(Elements::color(7)[1], 80);
  EXPECT_EQ(Elements::color(7)[2], 255);

  // Oxygen
  EXPECT_EQ(Elements::color(8)[0], 255);
  EXPECT_EQ(Elements::color(8)[1], 13);
  EXPECT_EQ(Elements::color(8)[2], 13);
}

TEST(ElementTest, dummyElement)
{
  EXPECT_EQ(Elements::radiusVDW(0), 0.69);
  EXPECT_EQ(Elements::radiusCovalent(0), 0.18);
}

TEST(ElementTest, customElements)
{
  for (unsigned char i = Avogadro::CustomElementMin;
       i <= Avogadro::CustomElementMax; ++i) {
    std::string name = Elements::name(i);
    std::string symbol = Elements::symbol(i);
    // These should not return the dummy labels
    EXPECT_TRUE(Avogadro::Core::isCustomElement(i));
    EXPECT_STRNE(name.c_str(), Elements::name(0));
    EXPECT_STRNE(symbol.c_str(), Elements::symbol(0));
    // The last two characters must match:
    EXPECT_EQ(name.substr(name.size() - 2), symbol.substr(symbol.size() - 2));
    // Round trip:
    EXPECT_EQ((int)Elements::atomicNumberFromName(name), (int)i);
    EXPECT_EQ((int)Elements::atomicNumberFromSymbol(symbol), (int)i);
  }
}
