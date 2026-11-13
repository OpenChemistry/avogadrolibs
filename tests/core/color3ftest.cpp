/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <type_traits>
#include <gtest/gtest.h>
#include <avogadro/core/color3f.h>

using Avogadro::Core::Color3f;

TEST(Color3fTest, constructorOverloads)
{
  EXPECT_TRUE((std::is_constructible_v<Color3f, float, float, float>));
  EXPECT_TRUE((std::is_constructible_v<Color3f, int, int, int>));
  // Three double arguments cause ambiguous overload resolution.
  EXPECT_FALSE((std::is_constructible_v<Color3f, double, double, double>));
}

TEST(Color3fTest, defaultConstructorF)
{
  Color3f color;

  EXPECT_FLOAT_EQ(color.red(), 0.0f);
  EXPECT_FLOAT_EQ(color.green(), 0.0f);
  EXPECT_FLOAT_EQ(color.blue(), 0.0f);
}

TEST(Color3fTest, oneArgumentConstructorF)
{
  Color3f color(0.5f);

  EXPECT_FLOAT_EQ(color.red(), 0.5f);
  EXPECT_FLOAT_EQ(color.green(), 0.0f);
  EXPECT_FLOAT_EQ(color.blue(), 0.0f);
}

TEST(Color3fTest, twoArgumentConstructorF)
{
  Color3f color(0.2f, 0.5f);

  EXPECT_FLOAT_EQ(color.red(), 0.2f);
  EXPECT_FLOAT_EQ(color.green(), 0.5f);
  EXPECT_FLOAT_EQ(color.blue(), 0.0f);
}

TEST(Color3fTest, threeArgumentConstructorF)
{
  Color3f color(0.2f, 0.5f, 0.9f);

  EXPECT_FLOAT_EQ(color.red(), 0.2f);
  EXPECT_FLOAT_EQ(color.green(), 0.5f);
  EXPECT_FLOAT_EQ(color.blue(), 0.9f);
}

TEST(Color3fTest, threeArgumentConstructorInt)
{
  Color3f color(43, 123, 195);

  EXPECT_NEAR(color.red(), 0.168627f, 1e-6f);
  EXPECT_NEAR(color.green(), 0.482353f, 1e-6f);
  EXPECT_NEAR(color.blue(), 0.764706f, 1e-6f);
}
