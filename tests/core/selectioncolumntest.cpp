/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/selectioncolumn.h>

#include <vector>

using Avogadro::Index;
using Avogadro::Core::SelectionColumn;

namespace {

SelectionColumn make(const std::vector<bool>& values)
{
  SelectionColumn column;
  column.storage() = values;
  return column;
}

} // namespace

TEST(SelectionColumnTest, defaultIsEmpty)
{
  SelectionColumn column;
  EXPECT_TRUE(column.empty());
  EXPECT_EQ(column.size(), static_cast<Index>(0));
  EXPECT_FALSE(column.hasEntry(0));
}

TEST(SelectionColumnTest, swapBothCovered)
{
  SelectionColumn column = make({ true, false, false });
  column.swapEntries(0, 2);
  EXPECT_EQ(column.storage(), (std::vector<bool>{ false, false, true }));
}

TEST(SelectionColumnTest, swapOnlyLowerCoveredGrows)
{
  SelectionColumn column = make({ false, true });
  column.swapEntries(1, 4);
  EXPECT_EQ(column.storage(),
            (std::vector<bool>{ false, false, false, false, true }));
  // Argument order does not matter.
  SelectionColumn other = make({ false, true });
  other.swapEntries(4, 1);
  EXPECT_EQ(other.storage(), column.storage());
}

TEST(SelectionColumnTest, swapNeitherCoveredDoesNothing)
{
  SelectionColumn column = make({ true });
  column.swapEntries(2, 3);
  EXPECT_EQ(column.size(), static_cast<Index>(1));
  SelectionColumn empty;
  empty.swapEntries(0, 1);
  EXPECT_TRUE(empty.empty());
}

TEST(SelectionColumnTest, removeFullSwapsAndPops)
{
  SelectionColumn column = make({ true, false, false, true });
  column.removeEntry(1, 4);
  EXPECT_EQ(column.storage(), (std::vector<bool>{ true, true, false }));
  // Removing the last one just pops.
  column.removeEntry(2, 3);
  EXPECT_EQ(column.storage(), (std::vector<bool>{ true, true }));
}

TEST(SelectionColumnTest, removeShortResetsOrIgnores)
{
  SelectionColumn column = make({ true, true });
  column.removeEntry(0, 5);
  EXPECT_EQ(column.storage(), (std::vector<bool>{ false, true }));
  column.removeEntry(3, 5);
  EXPECT_EQ(column.storage(), (std::vector<bool>{ false, true }));
  // An index past a full column is refused rather than read.
  column.removeEntry(2, 2);
  EXPECT_EQ(column.size(), static_cast<Index>(2));
}

TEST(SelectionColumnTest, trimClearTakeFrom)
{
  SelectionColumn column = make({ true, true, true });
  column.trimTo(5);
  EXPECT_EQ(column.size(), static_cast<Index>(3));
  column.trimTo(1);
  EXPECT_EQ(column.size(), static_cast<Index>(1));

  SelectionColumn target = make({ false, false });
  target.takeFrom(column);
  EXPECT_EQ(target.storage(), (std::vector<bool>{ true }));
  EXPECT_TRUE(column.empty());

  target.clear();
  EXPECT_TRUE(target.empty());
}

namespace {

void roundTrip(const std::vector<bool>& values, Index index, Index count,
               size_t savedEntries)
{
  SelectionColumn column = make(values);
  SelectionColumn saved = column.slice(index, count);
  EXPECT_EQ(saved.size(), static_cast<Index>(savedEntries));
  column.removeEntry(index, count);
  column.restore(index, saved, count);
  EXPECT_EQ(column.storage(), values);
}

} // namespace

TEST(SelectionColumnTest, sliceRestoreRoundTrip)
{
  roundTrip({ true, false, true, true }, 1, 4, 2); // full
  roundTrip({ true, false, true, true }, 3, 4, 2); // full, last
  roundTrip({ true, false }, 1, 5, 1);             // short, reaches
  roundTrip({ true, false }, 3, 5, 0);             // short, does not reach
  roundTrip({}, 0, 0, 0);
}
