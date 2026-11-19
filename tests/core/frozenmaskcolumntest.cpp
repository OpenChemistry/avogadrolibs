/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/frozenmaskcolumn.h>

#include <vector>

using Avogadro::Index;
using Avogadro::Core::FrozenMaskColumn;

namespace {

// One value per atom, repeated on all three axes.
FrozenMaskColumn make(const std::vector<double>& perAtom)
{
  FrozenMaskColumn column;
  column.storage().resize(static_cast<Eigen::Index>(3 * perAtom.size()));
  for (size_t i = 0; i < perAtom.size(); ++i)
    column.storage().segment<3>(3 * i).setConstant(perAtom[i]);
  return column;
}

std::vector<double> perAtom(const FrozenMaskColumn& column)
{
  std::vector<double> result;
  const auto& v = column.storage();
  for (Eigen::Index i = 0; i + 2 < v.rows(); i += 3) {
    EXPECT_EQ(v[i], v[i + 1]);
    EXPECT_EQ(v[i], v[i + 2]);
    result.push_back(v[i]);
  }
  EXPECT_EQ(v.rows() % 3, 0);
  return result;
}

using V = std::vector<double>;

} // namespace

TEST(FrozenMaskColumnTest, defaultIsEmpty)
{
  FrozenMaskColumn column;
  EXPECT_TRUE(column.empty());
  EXPECT_EQ(column.size(), static_cast<Index>(0));
  EXPECT_FALSE(column.hasEntry(0));
}

TEST(FrozenMaskColumnTest, sizeCountsAtoms)
{
  FrozenMaskColumn column = make({ 1.0, 0.0 });
  EXPECT_EQ(column.size(), static_cast<Index>(2));
  EXPECT_TRUE(column.hasEntry(1));
  EXPECT_FALSE(column.hasEntry(2));
  // A stray partial entry is not an entry, and is never read.
  column.storage().conservativeResize(7);
  EXPECT_EQ(column.size(), static_cast<Index>(2));
  EXPECT_FALSE(column.hasEntry(2));
}

TEST(FrozenMaskColumnTest, swapBothCovered)
{
  FrozenMaskColumn column = make({ 0.0, 1.0, 1.0 });
  column.swapEntries(0, 2);
  EXPECT_EQ(perAtom(column), (V{ 1.0, 1.0, 0.0 }));
}

TEST(FrozenMaskColumnTest, swapOnlyLowerCoveredGrows)
{
  FrozenMaskColumn column = make({ 1.0, 0.0 });
  column.swapEntries(1, 3);
  EXPECT_EQ(perAtom(column), (V{ 1.0, 1.0, 1.0, 0.0 }));
  FrozenMaskColumn other = make({ 1.0, 0.0 });
  other.swapEntries(3, 1);
  EXPECT_EQ(perAtom(other), perAtom(column));
}

TEST(FrozenMaskColumnTest, swapNeitherCoveredDoesNothing)
{
  FrozenMaskColumn column = make({ 0.0 });
  column.swapEntries(2, 3);
  EXPECT_EQ(perAtom(column), (V{ 0.0 }));
  FrozenMaskColumn empty;
  empty.swapEntries(0, 1);
  EXPECT_TRUE(empty.empty());
}

TEST(FrozenMaskColumnTest, swapKeepsAxesApart)
{
  FrozenMaskColumn column = make({ 1.0, 1.0 });
  column.storage()[1] = 0.0; // atom 0, y frozen
  column.swapEntries(0, 1);
  EXPECT_EQ(column.storage()[4], 0.0);
  EXPECT_EQ(column.storage()[1], 1.0);
}

TEST(FrozenMaskColumnTest, removeFullSwapsAndPops)
{
  FrozenMaskColumn column = make({ 1.0, 0.0, 1.0, 0.0 });
  column.removeEntry(1, 4);
  EXPECT_EQ(perAtom(column), (V{ 1.0, 0.0, 1.0 }));
  column.removeEntry(2, 3);
  EXPECT_EQ(perAtom(column), (V{ 1.0, 0.0 }));
}

TEST(FrozenMaskColumnTest, removeShortResetsOrIgnores)
{
  FrozenMaskColumn column = make({ 0.0, 0.0 });
  column.removeEntry(0, 5);
  EXPECT_EQ(perAtom(column), (V{ 1.0, 0.0 }));
  column.removeEntry(3, 5);
  EXPECT_EQ(perAtom(column), (V{ 1.0, 0.0 }));
  column.removeEntry(2, 2);
  EXPECT_EQ(column.size(), static_cast<Index>(2));
}

TEST(FrozenMaskColumnTest, raggedRowsDoNotOverrun)
{
  FrozenMaskColumn column;
  column.storage().setConstant(4, 0.0); // one entry plus a stray row
  column.removeEntry(1, 5);             // no entry for atom 1: nothing
  EXPECT_EQ(column.storage().rows(), 4);
  column.swapEntries(1, 2);
  EXPECT_EQ(column.storage().rows(), 4);
  FrozenMaskColumn saved = column.slice(1, 5);
  EXPECT_TRUE(saved.empty());
}

TEST(FrozenMaskColumnTest, clearTakeFrom)
{
  FrozenMaskColumn column = make({ 0.0 });

  FrozenMaskColumn target = make({ 1.0, 1.0 });
  target.takeFrom(column);
  EXPECT_EQ(perAtom(target), (V{ 0.0 }));
  EXPECT_TRUE(column.empty());

  target.clear();
  EXPECT_TRUE(target.empty());
}

namespace {

void roundTrip(const V& values, Index index, Index count, Index savedEntries)
{
  FrozenMaskColumn column = make(values);
  FrozenMaskColumn saved = column.slice(index, count);
  EXPECT_EQ(saved.size(), savedEntries);
  column.removeEntry(index, count);
  column.restore(index, saved, count);
  EXPECT_EQ(perAtom(column), values);
}

} // namespace

TEST(FrozenMaskColumnTest, sliceRestoreRoundTrip)
{
  roundTrip({ 1.0, 0.0, 1.0, 0.0 }, 1, 4, 2); // full
  roundTrip({ 1.0, 0.0, 1.0, 0.0 }, 3, 4, 2); // full, last
  roundTrip({ 1.0, 0.0 }, 1, 5, 1);           // short, reaches
  roundTrip({ 1.0, 0.0 }, 3, 5, 0);           // short, does not reach
  roundTrip({}, 0, 0, 0);
}
