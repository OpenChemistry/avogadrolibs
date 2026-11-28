/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/atomstate.h>
#include <avogadro/core/elements.h>

#include <string>

using Avogadro::Index;
using Avogadro::Vector2;
using Avogadro::Vector3ub;
using Avogadro::Core::Array;
using Avogadro::Core::AtomState;
using Avogadro::Core::Elements;

namespace {

const Index kAtoms = 5;

// C, H, O, N, S.
Array<unsigned char> makeNumbers()
{
  Array<unsigned char> numbers;
  for (unsigned char n : { 6, 1, 8, 7, 16 })
    numbers.push_back(n);
  return numbers;
}

Vector3ub elementColor(unsigned char number)
{
  return Vector3ub(Elements::color(number));
}

// Five atoms with columns of different lengths: 2D positions on three,
// labels on three, hybridizations on four, formal charges on all five,
// no isotopes, colors on two, selection on four, frozen mask on three,
// custom properties on four.
AtomState makeState()
{
  AtomState state;
  for (Index i = 0; i < 3; ++i) {
    state.positions2d.array().push_back(
      Vector2(static_cast<double>(i), 2.0 * static_cast<double>(i)));
    state.labels.array().push_back("label" + std::to_string(i));
  }
  for (Index i = 0; i < 4; ++i) {
    state.hybridizations.array().push_back(Avogadro::Core::SP3);
    state.selection.array().push_back(i % 2 == 0 ? 1 : 0);
    state.properties.setDouble("d", i, 0.5 * static_cast<double>(i));
    state.properties.setString("s", i, "s" + std::to_string(i));
  }
  state.hybridizations.array()[1] = Avogadro::Core::SP2;
  // disorder labels on three atoms
  for (Index i = 0; i < 3; ++i) {
    state.disorderAssemblies.array().push_back("A");
    state.disorderGroups.array().push_back(std::to_string(i + 1));
  }
  for (Index i = 0; i < kAtoms; ++i)
    state.formalCharges.array().push_back(static_cast<signed char>(i) - 2);
  state.colors.array().push_back(Vector3ub(1, 2, 3));
  state.colors.array().push_back(Vector3ub(4, 5, 6));
  state.frozenMask.storage().resize(9);
  state.frozenMask.storage().setOnes();
  state.frozenMask.storage().segment<3>(3).setZero();
  return state;
}

void expectSame(const AtomState& expected, const AtomState& actual, Index count)
{
  EXPECT_EQ(expected.positions2d.size(), actual.positions2d.size());
  EXPECT_EQ(expected.labels.size(), actual.labels.size());
  EXPECT_EQ(expected.hybridizations.size(), actual.hybridizations.size());
  EXPECT_EQ(expected.formalCharges.size(), actual.formalCharges.size());
  EXPECT_EQ(expected.isotopes.size(), actual.isotopes.size());
  EXPECT_EQ(expected.occupancies.size(), actual.occupancies.size());
  EXPECT_EQ(expected.disorderAssemblies.size(),
            actual.disorderAssemblies.size());
  EXPECT_EQ(expected.disorderGroups.size(), actual.disorderGroups.size());
  EXPECT_EQ(expected.colors.size(), actual.colors.size());
  EXPECT_EQ(expected.selection.size(), actual.selection.size());
  EXPECT_EQ(expected.frozenMask.size(), actual.frozenMask.size());
  EXPECT_EQ(expected.properties.doubles("d").size(),
            actual.properties.doubles("d").size());
  const Vector2 none(-1.0, -1.0);
  for (Index i = 0; i < count; ++i) {
    EXPECT_EQ(expected.positions2d.value(i, none),
              actual.positions2d.value(i, none))
      << i;
    EXPECT_EQ(expected.labels.value(i, "?"), actual.labels.value(i, "?")) << i;
    EXPECT_EQ(
      expected.hybridizations.value(i, Avogadro::Core::HybridizationUnknown),
      actual.hybridizations.value(i, Avogadro::Core::HybridizationUnknown))
      << i;
    EXPECT_EQ(expected.disorderGroups.value(i, "?"),
              actual.disorderGroups.value(i, "?"))
      << i;
    EXPECT_EQ(expected.disorderAssemblies.value(i, "?"),
              actual.disorderAssemblies.value(i, "?"))
      << i;
    EXPECT_EQ(expected.formalCharges.value(i, 99),
              actual.formalCharges.value(i, 99))
      << i;
    EXPECT_EQ(expected.colors.value(i, Vector3ub(9, 9, 9)),
              actual.colors.value(i, Vector3ub(9, 9, 9)))
      << i;
    EXPECT_EQ(expected.selection.value(i, 0), actual.selection.value(i, 0))
      << i;
    if (expected.frozenMask.hasEntry(i) && actual.frozenMask.hasEntry(i)) {
      EXPECT_TRUE(expected.frozenMask.storage().segment<3>(3 * i).isApprox(
        actual.frozenMask.storage().segment<3>(3 * i)))
        << i;
    }
    EXPECT_EQ(expected.properties.getDouble("d", i),
              actual.properties.getDouble("d", i))
      << i;
    EXPECT_EQ(expected.properties.getString("s", i),
              actual.properties.getString("s", i))
      << i;
  }
}

} // namespace

TEST(AtomStateTest, swapMovesEveryColumn)
{
  AtomState state = makeState();
  state.swapEntries(0, 3, makeNumbers());

  // Atom 0 had everything, atom 3 only a hybridization, charge, selection
  // flag and properties; each value travels with its atom.
  EXPECT_EQ(state.formalCharges.value(0, 99), 1);
  EXPECT_EQ(state.formalCharges.value(3, 99), -2);
  EXPECT_EQ(state.labels.value(3, "?"), "label0");
  EXPECT_EQ(state.labels.value(0, "?"), "");
  EXPECT_EQ(state.selection.array()[0], 0);
  EXPECT_EQ(state.selection.array()[3], 1);
  EXPECT_DOUBLE_EQ(state.properties.getDouble("d", 0).value(), 1.5);
  EXPECT_DOUBLE_EQ(state.properties.getDouble("d", 3).value(), 0.0);
}

TEST(AtomStateTest, swapGrowsColumnsWithTheirFills)
{
  AtomState state = makeState();
  const Array<unsigned char> numbers = makeNumbers();

  // Colors cover atoms 0-1 only. Swapping 1 and 4 grows them to cover 4:
  // atoms 2-3 get their element's color, and atom 4 (S) moves to 1.
  state.swapEntries(1, 4, numbers);
  ASSERT_EQ(state.colors.size(), static_cast<Index>(5));
  EXPECT_EQ(state.colors.array()[0], Vector3ub(1, 2, 3));
  EXPECT_EQ(state.colors.array()[1], elementColor(16));
  EXPECT_EQ(state.colors.array()[2], elementColor(8));
  EXPECT_EQ(state.colors.array()[3], elementColor(7));
  EXPECT_EQ(state.colors.array()[4], Vector3ub(4, 5, 6));

  // 2D positions cover 0-2; swapping 2 and 3 grows with zero, not garbage.
  state = makeState();
  state.swapEntries(2, 3, numbers);
  ASSERT_EQ(state.positions2d.size(), static_cast<Index>(4));
  EXPECT_EQ(state.positions2d.array()[2], Vector2(0.0, 0.0));
  EXPECT_EQ(state.positions2d.array()[3], Vector2(2.0, 4.0));

  // Neither atom has a label entry: nothing grows.
  state = makeState();
  const Index labelSize = state.labels.size();
  state.swapEntries(3, 4, numbers);
  EXPECT_EQ(state.labels.size(), labelSize);
}

TEST(AtomStateTest, removeMovesTheLastAtomIn)
{
  AtomState state = makeState();
  state.removeEntry(1, kAtoms, makeNumbers());

  // Formal charges cover every atom, so they reindex.
  ASSERT_EQ(state.formalCharges.size(), static_cast<Index>(4));
  EXPECT_EQ(state.formalCharges.value(1, 99), 2);
  // Colors are short: atom 1's stale value is reset to the color of the atom
  // that moved in (index 4, sulfur).
  ASSERT_EQ(state.colors.size(), static_cast<Index>(2));
  EXPECT_EQ(state.colors.array()[0], Vector3ub(1, 2, 3));
  EXPECT_EQ(state.colors.array()[1], elementColor(16));
  // Labels are short: the removed label must not stay behind.
  EXPECT_EQ(state.labels.value(1, "?"), "");
  EXPECT_EQ(state.labels.value(2, "?"), "label2");
  // Positions: reset to zero, not garbage.
  EXPECT_EQ(state.positions2d.array()[1], Vector2(0.0, 0.0));
  EXPECT_FALSE(state.properties.getString("s", 1).has_value());
}

TEST(AtomStateTest, colorFillNeverReadsOutOfBounds)
{
  const Array<unsigned char> numbers = makeNumbers();
  AtomState::ColorFill fill{ &numbers };
  EXPECT_EQ(fill(2), elementColor(8));
  // Past the end and null both give the color of atomic number 0.
  EXPECT_EQ(fill(kAtoms), elementColor(0));
  EXPECT_EQ(fill(Avogadro::MaxIndex), elementColor(0));
  EXPECT_EQ(AtomState::ColorFill()(0), elementColor(0));
}

TEST(AtomStateTest, clearEmptiesEverything)
{
  AtomState state = makeState();
  state.clear();
  EXPECT_TRUE(state.positions2d.empty());
  EXPECT_TRUE(state.labels.empty());
  EXPECT_TRUE(state.hybridizations.empty());
  EXPECT_TRUE(state.formalCharges.empty());
  EXPECT_TRUE(state.isotopes.empty());
  EXPECT_TRUE(state.occupancies.empty());
  EXPECT_TRUE(state.disorderAssemblies.empty());
  EXPECT_TRUE(state.disorderGroups.empty());
  EXPECT_TRUE(state.colors.empty());
  EXPECT_TRUE(state.selection.empty());
  EXPECT_TRUE(state.frozenMask.empty());
  EXPECT_TRUE(state.properties.empty());
}

TEST(AtomStateTest, addEntryOnlyExtendsProperties)
{
  AtomState state = makeState();
  state.addEntry(kAtoms + 1);
  EXPECT_EQ(state.properties.doubles("d").size(), static_cast<Index>(5));
  EXPECT_EQ(state.labels.size(), static_cast<Index>(3));
  EXPECT_EQ(state.formalCharges.size(), static_cast<Index>(5));
  EXPECT_EQ(state.colors.size(), static_cast<Index>(2));
}

TEST(AtomStateTest, sliceAndRestoreRoundTrip)
{
  const AtomState original = makeState();
  const Array<unsigned char> numbers = makeNumbers();
  for (Index index = 0; index < kAtoms; ++index) {
    SCOPED_TRACE("index " + std::to_string(index));
    AtomState state = original;
    const AtomState saved = state.slice(index, kAtoms);
    state.removeEntry(index, kAtoms, makeNumbers());
    ASSERT_EQ(state.formalCharges.size(), static_cast<Index>(4));
    state.restore(index, saved, kAtoms, numbers);
    expectSame(original, state, kAtoms);
  }
}

TEST(AtomStateTest, takeFromLeavesTheSourceDefault)
{
  AtomState source = makeState();
  AtomState target;
  target.takeFrom(source);
  expectSame(makeState(), target, kAtoms);
  EXPECT_TRUE(source.positions2d.empty());
  EXPECT_TRUE(source.labels.empty());
  EXPECT_TRUE(source.formalCharges.empty());
  EXPECT_TRUE(source.colors.empty());
  EXPECT_TRUE(source.selection.empty());
  EXPECT_TRUE(source.frozenMask.empty());
  EXPECT_TRUE(source.properties.empty());
}

TEST(AtomStateTest, forEachColumnVisitsEveryColumn)
{
  AtomState state = makeState();
  int visited = 0;
  state.forEachColumn(nullptr, [&](auto&, const auto&) { ++visited; });
  EXPECT_EQ(visited, 12);
}
