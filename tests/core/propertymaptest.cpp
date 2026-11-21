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

namespace {

// Compare two maps by what their public getters report, and by column size,
// for every index up to @p count.
void expectSameProperties(const PropertyMap& expected,
                          const PropertyMap& actual, Avogadro::Index count)
{
  EXPECT_EQ(expected.doubles("d").size(), actual.doubles("d").size());
  EXPECT_EQ(expected.ints("i").size(), actual.ints("i").size());
  EXPECT_EQ(expected.strings("s").size(), actual.strings("s").size());
  for (Avogadro::Index k = 0; k < count; ++k) {
    EXPECT_EQ(expected.getDouble("d", k), actual.getDouble("d", k)) << k;
    EXPECT_EQ(expected.getInt("i", k), actual.getInt("i", k)) << k;
    EXPECT_EQ(expected.getString("s", k), actual.getString("s", k)) << k;
    EXPECT_EQ(expected.hasMatrix("m", k), actual.hasMatrix("m", k)) << k;
    if (expected.hasMatrix("m", k) && actual.hasMatrix("m", k))
      EXPECT_EQ(expected.getMatrix("m", k).value()(0, 0),
                actual.getMatrix("m", k).value()(0, 0))
        << k;
  }
}

} // namespace

TEST(PropertyMapTest, sliceAndRestoreRoundTrip)
{
  const Avogadro::Index count = 5;
  // Doubles cover every entity, ints stop at 3 entries, strings at 1, and
  // the matrix column is sparse; the last entity has a matrix.
  PropertyMap map;
  for (Avogadro::Index k = 0; k < count; ++k)
    map.setDouble("d", k, 1.5 * static_cast<double>(k));
  for (Avogadro::Index k = 0; k < 3; ++k)
    map.setInt("i", k, 10 + static_cast<int>(k));
  map.setString("s", 0, "zero");
  for (Avogadro::Index k : { 1, 4 }) {
    Avogadro::MatrixX m(1, 1);
    m(0, 0) = 100.0 + static_cast<double>(k);
    map.setMatrix("m", k, m);
  }

  for (Avogadro::Index index = 0; index < count; ++index) {
    SCOPED_TRACE("index " + std::to_string(index));
    PropertyMap work = map;
    const PropertyMap saved = work.slice(index, count);
    work.removeEntry(index, count);
    work.restore(index, saved, count);
    expectSameProperties(map, work, count);
  }
}

TEST(PropertyMapTest, eraseEntryKeepsTheOrder)
{
  const Avogadro::Index count = 4;
  PropertyMap map;
  for (Avogadro::Index k = 0; k < count; ++k)
    map.setDouble("d", k, static_cast<double>(k));
  for (Avogadro::Index k : { 1, 3 }) {
    Avogadro::MatrixX m(1, 1);
    m(0, 0) = 100.0 + static_cast<double>(k);
    map.setMatrix("m", k, m);
  }

  map.eraseEntry(1, count);
  // The later entities move down by one; the last is not swapped in.
  ASSERT_EQ(map.doubles("d").size(), static_cast<size_t>(3));
  EXPECT_EQ(map.getDouble("d", 0), 0.0);
  EXPECT_EQ(map.getDouble("d", 1), 2.0);
  EXPECT_EQ(map.getDouble("d", 2), 3.0);
  EXPECT_FALSE(map.hasMatrix("m", 0));
  EXPECT_FALSE(map.hasMatrix("m", 1));
  EXPECT_FALSE(map.hasMatrix("m", 3));
  ASSERT_TRUE(map.hasMatrix("m", 2));
  EXPECT_EQ((*map.getMatrix("m", 2))(0, 0), 103.0);
}

TEST(PropertyMapTest, sliceEraseAndInsertRoundTrip)
{
  const Avogadro::Index count = 5;
  PropertyMap map;
  for (Avogadro::Index k = 0; k < count; ++k)
    map.setDouble("d", k, 1.5 * static_cast<double>(k));
  for (Avogadro::Index k = 0; k < 3; ++k)
    map.setInt("i", k, 10 + static_cast<int>(k));
  map.setString("s", 0, "zero");
  for (Avogadro::Index k : { 1, 4 }) {
    Avogadro::MatrixX m(1, 1);
    m(0, 0) = 100.0 + static_cast<double>(k);
    map.setMatrix("m", k, m);
  }

  for (Avogadro::Index index = 0; index < count; ++index) {
    SCOPED_TRACE("index " + std::to_string(index));
    PropertyMap work = map;
    const PropertyMap saved = work.slice(index, count);
    work.eraseEntry(index, count);
    work.insertEntry(index, saved, count);
    expectSameProperties(map, work, count);
  }

  // Taking out several, the way removing an atom can, and putting them back
  // in ascending order.
  PropertyMap work = map;
  const PropertyMap first = work.slice(1, count);
  const PropertyMap second = work.slice(3, count);
  work.eraseEntry(3, count);
  work.eraseEntry(1, count - 1);
  work.insertEntry(1, first, count - 1);
  work.insertEntry(3, second, count);
  expectSameProperties(map, work, count);
}

TEST(PropertyMapTest, sliceAndRestoreOnEmptyMap)
{
  PropertyMap map;
  const PropertyMap saved = map.slice(0, 1);
  map.removeEntry(0, 1);
  map.restore(0, saved, 1);
  EXPECT_TRUE(map.empty());
}

TEST(PropertyMapTest, eraseAndInsertOnEmptyMap)
{
  PropertyMap map;
  const PropertyMap saved = map.slice(0, 1);
  map.eraseEntry(0, 1);
  map.insertEntry(0, saved, 1);
  EXPECT_TRUE(map.empty());
}
