/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/variantmap.h>

using Avogadro::Core::VariantMap;

TEST(VariantMapTest, size)
{
  VariantMap map;
  EXPECT_EQ(map.size(), static_cast<size_t>(0));
}

TEST(VariantMapTest, isEmpty)
{
  VariantMap map;
  EXPECT_EQ(map.isEmpty(), true);

  map.setValue("value1", 1);
  EXPECT_EQ(map.isEmpty(), false);
  EXPECT_EQ(map.hasValue("value1"), true);
  EXPECT_EQ(map.hasValue("value2"), false);
  EXPECT_EQ(map.value("value1").toInt(), 1);
}
