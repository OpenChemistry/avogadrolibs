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
