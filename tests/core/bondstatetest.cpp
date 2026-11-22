/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/bondstate.h>

#include <string>
#include <utility>
#include <vector>

using Avogadro::Index;
using Avogadro::Core::BondState;

namespace {

// Four bonds with orders 1-4, labels on the first three only, and custom
// properties on all but the last.
BondState makeState()
{
  BondState state;
  for (unsigned char order = 1; order <= 4; ++order)
    state.orders.array().push_back(order);
  for (Index i = 0; i < 3; ++i)
    state.labels.set(i, "label" + std::to_string(i), 4);
  for (Index i = 0; i < 3; ++i) {
    state.properties.setDouble("d", i, 0.5 * static_cast<double>(i));
    state.properties.setString("s", i, "s" + std::to_string(i));
  }
  return state;
}

void expectSame(const BondState& expected, const BondState& actual, Index count)
{
  EXPECT_EQ(expected.orders.size(), actual.orders.size());
  EXPECT_EQ(expected.labels.size(), actual.labels.size());
  EXPECT_EQ(expected.properties.doubles("d").size(),
            actual.properties.doubles("d").size());
  for (Index i = 0; i < count; ++i) {
    EXPECT_EQ(expected.orders.value(i, 0), actual.orders.value(i, 0)) << i;
    EXPECT_EQ(expected.labels.value(i, "?"), actual.labels.value(i, "?")) << i;
    EXPECT_EQ(expected.properties.getDouble("d", i),
              actual.properties.getDouble("d", i))
      << i;
    EXPECT_EQ(expected.properties.getString("s", i),
              actual.properties.getString("s", i))
      << i;
  }
}

} // namespace

TEST(BondStateTest, swapMovesEveryColumn)
{
  BondState state = makeState();
  state.swapEntries(0, 3);
  EXPECT_EQ(state.orders.value(0, 0), 4);
  EXPECT_EQ(state.orders.value(3, 0), 1);
  // Bond 0 had a label, bond 3 did not: it travels with its bond.
  EXPECT_EQ(state.labels.value(0, "?"), "");
  EXPECT_EQ(state.labels.value(3, "?"), "label0");
  EXPECT_FALSE(state.properties.getDouble("d", 0).has_value());
  EXPECT_DOUBLE_EQ(state.properties.getDouble("d", 3).value(), 0.0);
}

TEST(BondStateTest, removeMovesTheLastBondIn)
{
  BondState state = makeState();
  state.removeEntry(1, 4);
  ASSERT_EQ(state.orders.size(), static_cast<Index>(3));
  EXPECT_EQ(state.orders.value(1, 0), 4);
  // The last bond had no label; the removed bond's must not stay behind.
  EXPECT_EQ(state.labels.value(1, "?"), "");
  EXPECT_FALSE(state.properties.getString("s", 1).has_value());
  EXPECT_EQ(state.labels.value(2, "?"), "label2");
}

TEST(BondStateTest, clearEmptiesEverything)
{
  BondState state = makeState();
  state.clear();
  EXPECT_TRUE(state.orders.empty());
  EXPECT_TRUE(state.labels.empty());
  EXPECT_TRUE(state.properties.empty());
}

TEST(BondStateTest, sliceAndRestoreRoundTrip)
{
  const BondState original = makeState();
  for (Index index = 0; index < 4; ++index) {
    SCOPED_TRACE("index " + std::to_string(index));
    BondState state = original;
    const BondState saved = state.slice(index, 4);
    state.removeEntry(index, 4);
    ASSERT_EQ(state.orders.size(), static_cast<Index>(3));
    state.restore(index, saved, 4);
    expectSame(original, state, 4);
  }
}

TEST(BondStateTest, takeFromLeavesTheSourceDefault)
{
  BondState source = makeState();
  BondState target;
  target.takeFrom(source);
  expectSame(makeState(), target, 4);
  EXPECT_TRUE(source.orders.empty());
  EXPECT_TRUE(source.labels.empty());
  EXPECT_TRUE(source.properties.empty());
}

TEST(BondStateTest, forEachColumnVisitsEveryColumn)
{
  BondState state = makeState();
  int visited = 0;
  state.forEachColumn([&](auto&) { ++visited; });
  EXPECT_EQ(visited, 3);
}
