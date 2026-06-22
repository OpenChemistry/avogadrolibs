/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/propertymap.h>

using Avogadro::Core::PropertyMap;

TEST(PropertyMapTest, createDoubles)
{
  PropertyMap map;
  map.createDoubles("energy", 3);

  EXPECT_TRUE(map.hasDoubles("energy"));
  EXPECT_EQ(map.doubles("energy").size(), static_cast<size_t>(3));

  // New columns are unset (sentinel) until a value is assigned.
  EXPECT_FALSE(map.getDouble("energy", 0).has_value());
  EXPECT_FALSE(map.getDouble("energy", 2).has_value());

  map.setDouble("energy", 1, 1.5);
  EXPECT_TRUE(map.getDouble("energy", 1).has_value());
  EXPECT_DOUBLE_EQ(map.getDouble("energy", 1).value(), 1.5);
}

TEST(PropertyMapTest, createInts)
{
  PropertyMap map;
  map.createInts("count", 2);

  EXPECT_TRUE(map.hasInts("count"));
  EXPECT_EQ(map.ints("count").size(), static_cast<size_t>(2));
  EXPECT_FALSE(map.getInt("count", 0).has_value());

  map.setInt("count", 0, 7);
  EXPECT_EQ(map.getInt("count", 0).value(), 7);
}

TEST(PropertyMapTest, createStrings)
{
  PropertyMap map;
  map.createStrings("label", 2);

  EXPECT_TRUE(map.hasStrings("label"));
  EXPECT_EQ(map.strings("label").size(), static_cast<size_t>(2));
  EXPECT_FALSE(map.getString("label", 0).has_value());

  map.setString("label", 1, "alpha");
  EXPECT_EQ(map.getString("label", 1).value(), "alpha");
}

TEST(PropertyMapTest, createDoesNotOverwriteExisting)
{
  PropertyMap map;
  map.setDouble("energy", 0, 3.14);

  // Creating a column that already exists must not clear it.
  map.createDoubles("energy", 5);
  EXPECT_TRUE(map.getDouble("energy", 0).has_value());
  EXPECT_DOUBLE_EQ(map.getDouble("energy", 0).value(), 3.14);
}
