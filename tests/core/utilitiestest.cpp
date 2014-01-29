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

#include <avogadro/core/utilities.h>

using std::string;
using Avogadro::Core::contains;
using Avogadro::Core::lexicalCast;
using Avogadro::Core::split;
using Avogadro::Core::startsWith;
using Avogadro::Core::trimmed;

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
