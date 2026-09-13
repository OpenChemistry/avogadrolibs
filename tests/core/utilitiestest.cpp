/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/utilities.h>

#include <limits>

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

TEST(UtilitiesTest, lexicalCastOutOfRange)
{
  // Some programs write exponents a double cannot represent. These are
  // effectively zero and should not abort reading the rest of a file.
  EXPECT_EQ(lexicalCast<double>("2.61793E-500"), 0.0);
  EXPECT_EQ(lexicalCast<double>("-7.5467E-6000"), 0.0);

  // Overflow is clamped rather than becoming an infinity.
  EXPECT_EQ(lexicalCast<double>("1.0E+500"),
            std::numeric_limits<double>::max());
  EXPECT_EQ(lexicalCast<double>("-1.0E+500"),
            std::numeric_limits<double>::lowest());

  // Values that are not numbers still fail, including the special literals.
  // Whether operator>> accepts these depends on the standard library, so keep
  // every spelling strtod would take covered on both libstdc++ and libc++.
  EXPECT_EQ(lexicalCast<double>("five"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("NaN"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("nan"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("-nan"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("inf"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("-inf"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>("infinity"), std::nullopt);
  EXPECT_EQ(lexicalCast<double>(""), std::nullopt);
}

TEST(UtilitiesTest, lexicalCastFloatOutOfRange)
{
  // The float extractor rejects a merely subnormal result, because strtof
  // reports underflow as ERANGE. Quantum chemistry codes write the decaying
  // tail of a density well past FLT_MIN, so these must still be read.
  EXPECT_NE(lexicalCast<float>("9.293354777E-39"), std::nullopt);
  EXPECT_NEAR(lexicalCast<float>("9.293354777E-39").value_or(-1.0f),
              9.293354777e-39f, 1.0e-40f);
  EXPECT_NEAR(lexicalCast<float>("1.505124610E-39").value_or(-1.0f),
              1.505124610e-39f, 1.0e-40f);

  // Below even a subnormal float, or below double, is effectively zero.
  EXPECT_EQ(lexicalCast<float>("1.0E-60"), 0.0f);
  EXPECT_EQ(lexicalCast<float>("2.61793E-500"), 0.0f);

  // Overflow is clamped rather than becoming an infinity, including a value
  // that is in range for double but not for float.
  EXPECT_EQ(lexicalCast<float>("1.0E+300"), std::numeric_limits<float>::max());
  EXPECT_EQ(lexicalCast<float>("-1.0E+300"),
            std::numeric_limits<float>::lowest());
  EXPECT_EQ(lexicalCast<float>("1.0E+500"), std::numeric_limits<float>::max());

  // Ordinary values are unaffected.
  EXPECT_FLOAT_EQ(lexicalCast<float>("1.000000000").value_or(0.0f), 1.0f);

  // Values that are not numbers still fail.
  EXPECT_EQ(lexicalCast<float>("five"), std::nullopt);
  EXPECT_EQ(lexicalCast<float>("nan"), std::nullopt);
  EXPECT_EQ(lexicalCast<float>("inf"), std::nullopt);
  EXPECT_EQ(lexicalCast<float>(""), std::nullopt);
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
