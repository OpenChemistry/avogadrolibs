#include <gtest/gtest.h>

#include <variantmap.h>

TEST(VariantMapTest, size)
{
  MolCore::VariantMap map;
  EXPECT_EQ(map.size(), 0);
}

TEST(VariantMapTest, isEmpty)
{
  MolCore::VariantMap map;
  EXPECT_EQ(map.isEmpty(), true);

  map.setValue("value1", 1);
  EXPECT_EQ(map.isEmpty(), false);
  EXPECT_EQ(map.value("value1").toInt(), 1);
}
