/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/column.h>
#include <avogadro/core/vector.h>

#include <string>
#include <utility>
#include <vector>

using Avogadro::Index;
using Avogadro::Core::Array;
using Avogadro::Core::Column;

namespace {

Column<std::string> makeLabels(const std::vector<std::string>& values)
{
  Column<std::string> column;
  for (const auto& v : values)
    column.array().push_back(v);
  return column;
}

std::vector<std::string> toVector(const Column<std::string>& column)
{
  return std::vector<std::string>(column.array().begin(), column.array().end());
}

} // namespace

TEST(ColumnTest, defaultIsEmpty)
{
  Column<int> column;
  EXPECT_EQ(column.size(), static_cast<Index>(0));
  EXPECT_FALSE(column.hasEntry(0));
  EXPECT_EQ(column.value(0, 7), 7);
}

TEST(ColumnTest, setGrowsToCount)
{
  Column<std::string> column;
  EXPECT_TRUE(column.set(2, "c", 5));
  EXPECT_EQ(column.size(), static_cast<Index>(5));
  EXPECT_EQ(column.value(0, "?"), "");
  EXPECT_EQ(column.value(2, "?"), "c");
  EXPECT_EQ(column.value(4, "?"), "");
  EXPECT_EQ(column.value(5, "?"), "?");
  // Out of range: refused, unchanged.
  EXPECT_FALSE(column.set(5, "x", 5));
  EXPECT_EQ(column.size(), static_cast<Index>(5));
}

TEST(ColumnTest, setWithinExistingEntriesDoesNotGrow)
{
  Column<int> column;
  column.set(0, 1, 2);
  column.set(1, 2, 2);
  EXPECT_TRUE(column.set(0, 9, 4));
  EXPECT_EQ(column.size(), static_cast<Index>(2));
  EXPECT_EQ(column.value(0, -1), 9);
}

TEST(ColumnTest, setAll)
{
  Column<int> column;
  Array<int> values;
  values.push_back(1);
  values.push_back(2);
  EXPECT_FALSE(column.setAll(values, 3, false));
  EXPECT_TRUE(column.empty());
  EXPECT_TRUE(column.setAll(values, 2, false));
  EXPECT_EQ(column.size(), static_cast<Index>(2));

  // Empty is "clear" only when accepted.
  Array<int> none;
  EXPECT_FALSE(column.setAll(none, 2, false));
  EXPECT_EQ(column.size(), static_cast<Index>(2));
  EXPECT_TRUE(column.setAll(none, 2, true));
  EXPECT_TRUE(column.empty());
}

TEST(ColumnTest, swapFullLength)
{
  auto column = makeLabels({ "a", "b", "c" });
  column.swapEntries(0, 2);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "c", "b", "a" }));
  column.swapEntries(1, 1);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "c", "b", "a" }));
}

TEST(ColumnTest, swapRagged)
{
  // Two entries for four entities.
  auto column = makeLabels({ "a", "b" });
  // Only the lower index has an entry: the value travels to the higher one.
  column.swapEntries(1, 3);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "a", "", "", "b" }));
  // Argument order does not matter.
  column = makeLabels({ "a", "b" });
  column.swapEntries(3, 0);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "", "b", "", "a" }));
  // Neither has an entry: nothing to do.
  column = makeLabels({ "a", "b" });
  column.swapEntries(2, 3);
  EXPECT_EQ(column.size(), static_cast<Index>(2));
  // Both do.
  column.swapEntries(0, 1);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "b", "a" }));
}

TEST(ColumnTest, removeFullLength)
{
  auto column = makeLabels({ "a", "b", "c", "d" });
  column.removeEntry(1, 4);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "a", "d", "c" }));
  column.removeEntry(2, 3);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "a", "d" }));
}

TEST(ColumnTest, removeRagged)
{
  // Reaches the removed index: the entity moved in has no entry.
  auto column = makeLabels({ "a", "b" });
  column.removeEntry(0, 4);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "", "b" }));
  // Does not reach it: unchanged.
  column.removeEntry(3, 4);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "", "b" }));
}

TEST(ColumnTest, fillCallableAndValue)
{
  using Avogadro::Vector3;
  Column<Vector3> column;
  auto fill = [](Index i) { return Vector3(static_cast<double>(i), 0, 0); };
  EXPECT_TRUE(column.set(1, Vector3(5, 5, 5), 3, fill));
  EXPECT_EQ(column.size(), static_cast<Index>(3));
  EXPECT_EQ(column.value(0, Vector3::Zero()), Vector3(0, 0, 0));
  EXPECT_EQ(column.value(2, Vector3::Zero()), Vector3(2, 0, 0));

  // A plain value fills the same way.
  Column<Vector3> other;
  other.set(0, Vector3(1, 1, 1), 1);
  other.swapEntries(0, 2, Vector3(9, 9, 9));
  EXPECT_EQ(other.size(), static_cast<Index>(3));
  EXPECT_EQ(other.value(0, Vector3::Zero()), Vector3(9, 9, 9));
  EXPECT_EQ(other.value(1, Vector3::Zero()), Vector3(9, 9, 9));
  EXPECT_EQ(other.value(2, Vector3::Zero()), Vector3(1, 1, 1));

  // Growing with a plain value fills the new entries with it.
  Column<Vector3> grown;
  EXPECT_TRUE(grown.set(2, Vector3(1, 1, 1), 3, Vector3(9, 9, 9)));
  EXPECT_EQ(grown.value(0, Vector3::Zero()), Vector3(9, 9, 9));
  EXPECT_EQ(grown.value(1, Vector3::Zero()), Vector3(9, 9, 9));

  // Swap-and-pop fills the stale slot with the last entity's fill.
  Column<Vector3> ragged;
  ragged.set(0, Vector3(4, 4, 4), 1);
  ragged.removeEntry(0, 3, fill);
  EXPECT_EQ(ragged.size(), static_cast<Index>(1));
  EXPECT_EQ(ragged.value(0, Vector3::Zero()), Vector3(2, 0, 0));
}

TEST(ColumnTest, sliceAndRestoreRoundTrip)
{
  // Full length and ragged columns, at every index including past the end of
  // the ragged one.
  const std::vector<std::vector<std::string>> cases = {
    { "a", "b", "c", "d" }, { "a", "b", "c" }, { "a" }, { "a", "b" }, {}
  };
  const Index count = 4;
  for (const auto& values : cases) {
    for (Index index = 0; index < count; ++index) {
      SCOPED_TRACE("size " + std::to_string(values.size()) + " index " +
                   std::to_string(index));
      const auto original = makeLabels(values);
      auto column = original;
      const auto saved = column.slice(index, count);
      column.removeEntry(index, count);
      column.restore(index, saved, count);
      EXPECT_EQ(toVector(column), toVector(original));
    }
  }
}

TEST(ColumnTest, sliceContents)
{
  const auto full = makeLabels({ "a", "b", "c" });
  auto saved = full.slice(0, 3);
  EXPECT_EQ(toVector(saved), (std::vector<std::string>{ "a", "c" }));
  saved = full.slice(2, 3);
  EXPECT_EQ(toVector(saved), (std::vector<std::string>{ "c", "c" }));
  const auto ragged = makeLabels({ "a", "b" });
  EXPECT_EQ(toVector(ragged.slice(1, 3)), (std::vector<std::string>{ "b" }));
  EXPECT_TRUE(ragged.slice(2, 3).empty());
}

TEST(ColumnTest, restoreIgnoresAColumnThatNoLongerMatches)
{
  auto column = makeLabels({ "a", "b", "c" });
  const auto saved = column.slice(0, 3);
  // Not the state removeEntry() leaves: the size is wrong, so nothing happens.
  column.restore(0, saved, 3);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "a", "b", "c" }));
}

// A setter that is undone leaves the column it grew behind, so a column that
// did not reach the entity when it was removed may reach it when it comes back.
TEST(ColumnTest, restoreWithFillCopesWithAColumnThatGrewMeanwhile)
{
  // Entities 0..3 are "a".."d" in a column that stops before entity 2.
  auto original = makeLabels({ "a", "b" });
  const Index count = 4;
  const auto fill = [](Index index) { return std::string(1, 'p' + index); };
  const auto saved = original.slice(2, count);
  ASSERT_TRUE(saved.empty());
  auto column = original;
  column.removeEntry(2, count, fill);

  // Meanwhile the column grew to cover the three entities that are left, the
  // last one (the moved entity, now at index 2) holding its own default.
  column.set(2, fill(3), count - 1, fill);
  ASSERT_EQ(toVector(column), (std::vector<std::string>{ "a", "b", "s" }));

  // Its default is not needed: index 2 is the restored entity's default.
  column.restore(2, saved, count, fill);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "a", "b", "r" }));

  // A real value of the moved entity goes back to the end with it.
  column = original;
  column.removeEntry(2, count, fill);
  column.set(2, "real", count - 1, fill);
  column.restore(2, saved, count, fill);
  EXPECT_EQ(toVector(column),
            (std::vector<std::string>{ "a", "b", "r", "real" }));

  // Without the growth nothing changes.
  column = original;
  column.removeEntry(2, count, fill);
  column.restore(2, saved, count, fill);
  EXPECT_EQ(toVector(column), toVector(original));
}

TEST(ColumnTest, copyConstructionSharesAssignmentCopies)
{
  auto original = makeLabels({ "a", "b" });
  Column<std::string> shared(original);
  // Shared until written to.
  EXPECT_EQ(&std::as_const(shared).array()[0],
            &std::as_const(original).array()[0]);
  Column<std::string> assigned;
  assigned = original;
  EXPECT_NE(&std::as_const(assigned).array()[0],
            &std::as_const(original).array()[0]);
  assigned.set(0, "z", 2);
  EXPECT_EQ(original.value(0, "?"), "a");
}

TEST(ColumnTest, takeFromLeavesSourceEmpty)
{
  auto source = makeLabels({ "a", "b" });
  Column<std::string> target = makeLabels({ "x" });
  target.takeFrom(source);
  EXPECT_EQ(toVector(target), (std::vector<std::string>{ "a", "b" }));
  EXPECT_TRUE(source.empty());
  source.set(0, "n", 1);
  EXPECT_EQ(source.size(), static_cast<Index>(1));
}

TEST(ColumnTest, addEntryAppendsAndDropsStaleEntries)
{
  auto column = makeLabels({ "a", "b" });
  column.addEntry(3, "c");
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "a", "b", "c" }));

  // Entries past the new entity's index belong to no entity.
  auto stale = makeLabels({ "a", "b", "x", "y" });
  stale.addEntry(3, "c");
  EXPECT_EQ(toVector(stale), (std::vector<std::string>{ "a", "b", "c" }));

  Column<std::string> empty;
  empty.addEntry(1, "z");
  EXPECT_EQ(toVector(empty), (std::vector<std::string>{ "z" }));
}

TEST(ColumnTest, removeEntryDropsEntriesPastTheCount)
{
  // Four entries for three entities: the extra one belongs to no entity.
  auto column = makeLabels({ "a", "b", "c", "x" });
  column.removeEntry(0, 3, "?");
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "c", "b" }));
}

TEST(ColumnTest, sliceAndRestoreOnAnOverLongColumn)
{
  auto column = makeLabels({ "a", "b", "c", "x" });
  const auto original = toVector(column);
  const auto saved = column.slice(0, 3);
  EXPECT_EQ(toVector(saved), (std::vector<std::string>{ "a", "c" }));
  column.removeEntry(0, 3, "?");
  column.restore(0, saved, 3);
  // The entry past the count is gone; the rest is as it was.
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "a", "b", "c" }));
  EXPECT_EQ(original.size(), static_cast<size_t>(4));
}

TEST(ColumnTest, eraseEntryKeepsTheOrder)
{
  auto column = makeLabels({ "a", "b", "c", "d" });
  column.eraseEntry(1, 4);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "a", "c", "d" }));
  column.eraseEntry(2, 3);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "a", "c" }));
  column.eraseEntry(0, 2);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "c" }));
}

TEST(ColumnTest, eraseEntryOnAShortColumn)
{
  // Three entries for five entities: erasing past the end changes nothing,
  // erasing within it shortens the column.
  auto column = makeLabels({ "a", "b", "c" });
  column.eraseEntry(4, 5);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "a", "b", "c" }));
  column.eraseEntry(0, 5);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "b", "c" }));
  // Entries past the count belong to no entity and go first.
  auto longer = makeLabels({ "a", "b", "c", "x" });
  longer.eraseEntry(0, 3);
  EXPECT_EQ(toVector(longer), (std::vector<std::string>{ "b", "c" }));
  Column<std::string> empty;
  empty.eraseEntry(0, 1);
  EXPECT_TRUE(empty.empty());
}

TEST(ColumnTest, sliceEraseAndInsertRoundTrip)
{
  // A column covering every entity and one that stops short of the end.
  for (const auto& values :
       { std::vector<std::string>{ "a", "b", "c", "d" },
         std::vector<std::string>{ "a", "b" }, std::vector<std::string>{} }) {
    for (Index index = 0; index < 4; ++index) {
      SCOPED_TRACE("size " + std::to_string(values.size()) + ", index " +
                   std::to_string(index));
      auto column = makeLabels(values);
      const auto saved = column.slice(index, 4);
      column.eraseEntry(index, 4);
      column.insertEntry(index, saved, 4);
      EXPECT_EQ(toVector(column), values);
    }
  }
}

TEST(ColumnTest, insertEntryIgnoresAnEmptySlice)
{
  auto column = makeLabels({ "a" });
  column.insertEntry(0, Column<std::string>(), 2);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "a" }));
}

TEST(ColumnTest, insertValueShiftsTheEntriesAbove)
{
  auto column = makeLabels({ "a", "b", "c" });
  column.insertValue(1, "x", 4);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "a", "x", "b", "c" }));
  // Entries past the new count belong to no entity and are dropped.
  column.insertValue(0, "y", 4);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "y", "a", "x", "b" }));
}

TEST(ColumnTest, insertValueLeavesAShortColumnAlone)
{
  auto column = makeLabels({ "a", "b" });
  column.insertValue(2, "x", 4);
  column.insertValue(3, "x", 4);
  EXPECT_EQ(toVector(column), (std::vector<std::string>{ "a", "b" }));
  Column<std::string> empty;
  empty.insertValue(0, "x", 1);
  EXPECT_TRUE(empty.empty());
}
