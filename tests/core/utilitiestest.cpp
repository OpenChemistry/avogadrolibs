/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/utilities.h>

using Avogadro::Core::contains;
using Avogadro::Core::lexicalCast;
using Avogadro::Core::split;
using Avogadro::Core::startsWith;
using Avogadro::Core::trimmed;
using std::string;

TEST(UtilitiesTest, split)
{
  string test(" trim white space    ");
  EXPECT_EQ(split(test, ' ').size(), 3);
}

TEST(UtilitiesTest, splitEmpty)
{
  string test(" trim white space    ");
  EXPECT_EQ(split(test, ' ', false).size(), 7);
}

TEST(UtilitiesTest, trimmed)
{
  string test(" trim white space \n\t\r");
  EXPECT_EQ(trimmed(test), "trim white space");
  EXPECT_EQ(trimmed("test"), "test");
  EXPECT_EQ(trimmed("H"), "H");
  EXPECT_EQ(trimmed("  H"), "H");
  EXPECT_EQ(trimmed("H  "), "H");
  EXPECT_EQ(trimmed(" H  "), "H");
}

TEST(UtilitiesTest, lexicalCast)
{
  EXPECT_EQ(lexicalCast<int>("5"), 5);
  EXPECT_EQ(lexicalCast<double>("5.3"), 5.3);
  EXPECT_EQ(lexicalCast<double>("5.3E-10"), 5.3e-10);
}

TEST(UtilitiesTest, lexicalCastCheck)
{
  // Something simple that should pass.
  bool ok(false);
  lexicalCast<int>("5", ok);
  EXPECT_EQ(ok, true);

  // Pass something in that should fail.
  lexicalCast<int>("five", ok);
  EXPECT_EQ(ok, false);
}

TEST(UtilitiesTest, lexicalCastVector)
{
  {
    std::vector<std::string> strings{ "8.314", "6.02e23" };
    auto values = lexicalCast<double>(strings.begin(), strings.end());
    ASSERT_TRUE(values.has_value());
    EXPECT_EQ(values->size(), 2);
  }

  {
    std::vector<std::string> strings{ "96485", "XYZ", "137" };
    auto values = lexicalCast<int>(strings.begin(), strings.end());
    EXPECT_FALSE(values.has_value());
  }
}

TEST(UtilitiesTest, contains)
{
  EXPECT_TRUE(contains("hasFoo", "has"));
  EXPECT_TRUE(contains("hasFoo", "Foo"));
  EXPECT_FALSE(contains("hasFoo", "bar"));
}

TEST(UtilitiesTest, startsWith)
{
  EXPECT_TRUE(startsWith("hasFoo", "has"));
  EXPECT_FALSE(startsWith("hasFoo", "Foo"));
  EXPECT_FALSE(startsWith("hasFoo", "bar"));
}
