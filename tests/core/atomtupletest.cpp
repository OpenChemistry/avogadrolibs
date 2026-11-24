/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/atomtuple.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include <cmath>
#include <limits>
#include <tuple>
#include <vector>

using Avogadro::Index;
using Avogadro::MaxIndex;
using Avogadro::Real;
using Avogadro::Vector3;
using Avogadro::Core::Array;
using Avogadro::Core::AtomTuple;
using Avogadro::Core::Constraint;
using Avogadro::Core::UnitCell;

namespace {
const double tol = 1.0e-6;
using Kind = AtomTuple::Kind;

std::vector<Index> atomsOf(const AtomTuple& tuple)
{
  std::vector<Index> atoms;
  for (Index i : tuple)
    atoms.push_back(i);
  return atoms;
}

Array<Vector3> pts(const std::vector<Vector3>& points)
{
  Array<Vector3> positions;
  for (const Vector3& p : points)
    positions.push_back(p);
  return positions;
}

AtomTuple fromPadded(Index a, Index b, Index c, Index d)
{
  // A gap (c unset but d set) names nothing.
  if (c == MaxIndex && d != MaxIndex)
    return AtomTuple();
  if (c == MaxIndex)
    return AtomTuple(a, b);
  if (d == MaxIndex)
    return AtomTuple(a, b, c);
  return AtomTuple(a, b, c, d);
}
} // namespace

TEST(AtomTupleTest, defaultIsNone)
{
  AtomTuple tuple;
  EXPECT_EQ(tuple.kind(), Kind::None);
  EXPECT_FALSE(tuple.isValid());
  EXPECT_EQ(tuple.size(), 0u);
  EXPECT_EQ(tuple.atom(0), MaxIndex);
  EXPECT_TRUE(atomsOf(tuple).empty());
}

TEST(AtomTupleTest, constructorsSetKindAndSize)
{
  AtomTuple d(1, 2);
  EXPECT_EQ(d.kind(), Kind::Distance);
  EXPECT_EQ(d.size(), 2u);
  EXPECT_TRUE(d.isValid());

  AtomTuple a(1, 2, 3);
  EXPECT_EQ(a.kind(), Kind::Angle);
  EXPECT_EQ(a.size(), 3u);

  AtomTuple t(1, 2, 3, 4);
  EXPECT_EQ(t.kind(), Kind::Dihedral);
  EXPECT_EQ(t.size(), 4u);

  AtomTuple o = AtomTuple::outOfPlane(1, 2, 3, 4);
  EXPECT_EQ(o.kind(), Kind::OutOfPlane);
  EXPECT_EQ(o.size(), 4u);
  EXPECT_EQ(o.atom(0), 1u);
  EXPECT_EQ(o.atom(3), 4u);
}

TEST(AtomTupleTest, tupleConstructors)
{
  AtomTuple a(std::make_tuple(Index(5), Index(6), Index(7)));
  EXPECT_EQ(a, AtomTuple(5, 6, 7));
  EXPECT_EQ(a.kind(), Kind::Angle);

  AtomTuple t(std::make_tuple(Index(5), Index(6), Index(7), Index(8)));
  EXPECT_EQ(t, AtomTuple(5, 6, 7, 8));
  EXPECT_EQ(t.kind(), Kind::Dihedral);
}

TEST(AtomTupleTest, maxIndexMakesNone)
{
  EXPECT_FALSE(AtomTuple(MaxIndex, 1).isValid());
  EXPECT_FALSE(AtomTuple(1, MaxIndex).isValid());
  EXPECT_FALSE(AtomTuple(MaxIndex, 1, 2).isValid());
  EXPECT_FALSE(AtomTuple(1, MaxIndex, 2).isValid());
  EXPECT_FALSE(AtomTuple(1, 2, MaxIndex).isValid());
  EXPECT_FALSE(AtomTuple(MaxIndex, 1, 2, 3).isValid());
  EXPECT_FALSE(AtomTuple(1, MaxIndex, 2, 3).isValid());
  EXPECT_FALSE(AtomTuple(1, 2, MaxIndex, 3).isValid());
  EXPECT_FALSE(AtomTuple(1, 2, 3, MaxIndex).isValid());
  EXPECT_FALSE(AtomTuple::outOfPlane(1, 2, 3, MaxIndex).isValid());
  EXPECT_FALSE(AtomTuple::outOfPlane(MaxIndex, 2, 3, 4).isValid());

  AtomTuple none(1, MaxIndex);
  EXPECT_EQ(none.size(), 0u);
  EXPECT_EQ(none.atom(0), MaxIndex);
  EXPECT_EQ(none, AtomTuple());
}

TEST(AtomTupleTest, repeatedAtomMakesNone)
{
  EXPECT_FALSE(AtomTuple(1, 1).isValid());
  EXPECT_FALSE(AtomTuple(1, 2, 1).isValid());
  EXPECT_FALSE(AtomTuple(1, 1, 2).isValid());
  EXPECT_FALSE(AtomTuple(1, 2, 3, 2).isValid());
  EXPECT_FALSE(AtomTuple(1, 2, 3, 1).isValid());
  EXPECT_FALSE(AtomTuple::outOfPlane(1, 2, 3, 3).isValid());
  EXPECT_FALSE(
    AtomTuple(std::make_tuple(Index(1), Index(2), Index(1))).isValid());
  EXPECT_EQ(AtomTuple(1, 2, 3, 2).size(), 0u);
}

TEST(AtomTupleTest, atomAndRangeFor)
{
  AtomTuple t(4, 5, 6, 7);
  EXPECT_EQ(t.atom(0), 4u);
  EXPECT_EQ(t.atom(3), 7u);
  EXPECT_EQ(t.atom(4), MaxIndex);
  EXPECT_EQ(atomsOf(t), (std::vector<Index>{ 4, 5, 6, 7 }));

  AtomTuple a(4, 5, 6);
  EXPECT_EQ(a.atom(3), MaxIndex);
  EXPECT_EQ(atomsOf(a), (std::vector<Index>{ 4, 5, 6 }));

  AtomTuple d(4, 5);
  EXPECT_EQ(d.atom(2), MaxIndex);
  EXPECT_EQ(atomsOf(d), (std::vector<Index>{ 4, 5 }));
}

TEST(AtomTupleTest, reversed)
{
  EXPECT_EQ(AtomTuple(1, 2).reversed(), AtomTuple(2, 1));
  EXPECT_EQ(AtomTuple(1, 2, 3).reversed(), AtomTuple(3, 2, 1));
  EXPECT_EQ(AtomTuple(1, 2, 3, 4).reversed(), AtomTuple(4, 3, 2, 1));
  EXPECT_EQ(AtomTuple(1, 2, 3, 4).reversed().reversed(), AtomTuple(1, 2, 3, 4));

  AtomTuple o = AtomTuple::outOfPlane(1, 2, 3, 4);
  EXPECT_EQ(o.reversed(), o);
  EXPECT_EQ(AtomTuple().reversed(), AtomTuple());
}

TEST(AtomTupleTest, matchesEitherDirection)
{
  EXPECT_TRUE(AtomTuple(1, 2).matches(AtomTuple(1, 2)));
  EXPECT_TRUE(AtomTuple(1, 2).matches(AtomTuple(2, 1)));
  EXPECT_TRUE(AtomTuple(1, 2, 3).matches(AtomTuple(1, 2, 3)));
  EXPECT_TRUE(AtomTuple(1, 2, 3).matches(AtomTuple(3, 2, 1)));
  EXPECT_TRUE(AtomTuple(1, 2, 3, 4).matches(AtomTuple(1, 2, 3, 4)));
  EXPECT_TRUE(AtomTuple(1, 2, 3, 4).matches(AtomTuple(4, 3, 2, 1)));
}

TEST(AtomTupleTest, matchesRejectsOtherOrders)
{
  EXPECT_FALSE(AtomTuple(1, 2, 3).matches(AtomTuple(2, 1, 3)));
  EXPECT_FALSE(AtomTuple(1, 2, 3).matches(AtomTuple(1, 3, 2)));
  EXPECT_FALSE(AtomTuple(1, 2, 3, 4).matches(AtomTuple(4, 3, 1, 2)));
  EXPECT_FALSE(AtomTuple(1, 2, 3, 4).matches(AtomTuple(2, 1, 3, 4)));
  EXPECT_FALSE(AtomTuple(1, 2).matches(AtomTuple(1, 3)));
}

TEST(AtomTupleTest, outOfPlaneMatchesOnlyExact)
{
  AtomTuple o = AtomTuple::outOfPlane(1, 2, 3, 4);
  EXPECT_TRUE(o.matches(AtomTuple::outOfPlane(1, 2, 3, 4)));
  EXPECT_FALSE(o.matches(AtomTuple::outOfPlane(4, 3, 2, 1)));
  EXPECT_FALSE(o.matches(AtomTuple::outOfPlane(1, 3, 2, 4)));
  // The same atoms as a dihedral are a different kind.
  EXPECT_FALSE(o.matches(AtomTuple(1, 2, 3, 4)));
  EXPECT_FALSE(AtomTuple(1, 2, 3, 4).matches(o));
}

TEST(AtomTupleTest, differentKindsNeverMatch)
{
  EXPECT_FALSE(AtomTuple(1, 2).matches(AtomTuple(1, 2, 3)));
  EXPECT_FALSE(AtomTuple(1, 2, 3).matches(AtomTuple(1, 2)));
  EXPECT_FALSE(AtomTuple(1, 2, 3).matches(AtomTuple(1, 2, 3, 4)));
  EXPECT_FALSE(AtomTuple(1, 2, 3, 4).matches(AtomTuple(1, 2, 3)));
}

TEST(AtomTupleTest, noneMatchesNothing)
{
  AtomTuple none;
  EXPECT_FALSE(none.matches(none));
  EXPECT_FALSE(none.matches(AtomTuple(1, 2)));
  EXPECT_FALSE(AtomTuple(1, 2).matches(none));
  EXPECT_FALSE(AtomTuple(1, 1).matches(AtomTuple(1, 1)));
}

TEST(AtomTupleTest, equalityIsOrderSensitive)
{
  EXPECT_TRUE(AtomTuple(1, 2) == AtomTuple(1, 2));
  EXPECT_FALSE(AtomTuple(1, 2) == AtomTuple(2, 1));
  EXPECT_TRUE(AtomTuple(1, 2) != AtomTuple(2, 1));
  EXPECT_FALSE(AtomTuple(1, 2, 3) == AtomTuple(3, 2, 1));
  EXPECT_FALSE(AtomTuple(1, 2, 3, 4) == AtomTuple::outOfPlane(1, 2, 3, 4));
  EXPECT_TRUE(AtomTuple() == AtomTuple());
  EXPECT_FALSE(AtomTuple(1, 2) != AtomTuple(1, 2));
}

TEST(AtomTupleTest, agreesWithConstraintMatches)
{
  const Index M = MaxIndex;
  struct Case
  {
    Index a, b, c, d;
  };
  const std::vector<Case> constraints{
    { 1, 2, M, M },
    { 1, 2, 3, M },
    { 1, 2, 3, 4 },
  };
  const std::vector<Case> queries{
    { 1, 2, M, M }, { 2, 1, M, M }, { 1, 3, M, M }, { 1, 2, 3, M },
    { 3, 2, 1, M }, { 2, 1, 3, M }, { 1, 3, 2, M }, { 1, 2, 3, 4 },
    { 4, 3, 2, 1 }, { 4, 3, 1, 2 }, { 2, 1, 3, 4 }, { 1, 2, M, 4 },
    { 1, 2, 3, 1 }, { 1, 2, 3, 2 }
  };

  for (const Case& c : constraints) {
    Constraint constraint(c.a, c.b, c.c, c.d);
    AtomTuple own = fromPadded(c.a, c.b, c.c, c.d);
    for (const Case& q : queries) {
      // Constraint rejects gaps; AtomTuple rejects them as Kind::None.
      EXPECT_EQ(constraint.matches(q.a, q.b, q.c, q.d),
                own.matches(fromPadded(q.a, q.b, q.c, q.d)))
        << "constraint " << c.a << "," << c.b << "," << c.c << "," << c.d
        << " query " << q.a << "," << q.b << "," << q.c << "," << q.d;
    }
  }
}

TEST(AtomTupleTest, measureDistance)
{
  Array<Vector3> positions = pts({ Vector3(0, 0, 0), Vector3(3, 4, 0) });
  auto value = AtomTuple(0, 1).measure(positions);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, 5.0, tol);
  value = AtomTuple(0, 1).reversed().measure(positions);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, 5.0, tol);
}

TEST(AtomTupleTest, measureAngle)
{
  Array<Vector3> right =
    pts({ Vector3(1, 0, 0), Vector3(0, 0, 0), Vector3(0, 1, 0) });
  auto value = AtomTuple(0, 1, 2).measure(right);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, 90.0, tol);
  value = AtomTuple(0, 1, 2).reversed().measure(right);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, 90.0, tol);

  Array<Vector3> linear =
    pts({ Vector3(-1, 0, 0), Vector3(0, 0, 0), Vector3(1, 0, 0) });
  value = AtomTuple(0, 1, 2).measure(linear);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, 180.0, tol);

  Array<Vector3> coincident =
    pts({ Vector3(0, 0, 0), Vector3(0, 0, 0), Vector3(1, 0, 0) });
  value = AtomTuple(0, 1, 2).measure(coincident);
  ASSERT_TRUE(value.has_value());
  EXPECT_FALSE(std::isnan(*value));
  EXPECT_NEAR(*value, 0.0, tol);
}

TEST(AtomTupleTest, measureDihedralSign)
{
  const Real c60 = std::cos(60.0 * M_PI / 180.0);
  const Real s60 = std::sin(60.0 * M_PI / 180.0);
  auto build = [](const Vector3& d) {
    return pts({ Vector3(1, 0, 0), Vector3(0, 0, 0), Vector3(0, 0, 1), d });
  };
  AtomTuple dihedral(0, 1, 2, 3);

  Array<Vector3> plus = build(Vector3(c60, s60, 1));
  auto value = dihedral.measure(plus);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, 60.0, tol);
  value = dihedral.reversed().measure(plus);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, 60.0, tol);

  Array<Vector3> minus = build(Vector3(c60, -s60, 1));
  value = dihedral.measure(minus);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, -60.0, tol);
  value = dihedral.reversed().measure(minus);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, -60.0, tol);

  Array<Vector3> anti = build(Vector3(-1, 0, 1));
  value = dihedral.measure(anti);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(std::abs(*value), 180.0, tol);
  value = dihedral.reversed().measure(anti);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(std::abs(*value), 180.0, tol);
}

TEST(AtomTupleTest, measureOutOfPlane)
{
  auto build = [](const Vector3& d) {
    return pts({ Vector3(0, 0, 0), Vector3(1, 0, 0), Vector3(0, 1, 0), d });
  };
  AtomTuple wilson = AtomTuple::outOfPlane(0, 1, 2, 3);

  auto value = wilson.measure(build(Vector3(0, 0, 1)));
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, 90.0, tol);

  value = wilson.measure(build(Vector3(0, 0, -1)));
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, -90.0, tol);

  value = wilson.measure(build(Vector3(1, 1, 0)));
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, 0.0, tol);
}

TEST(AtomTupleTest, measureOutOfRangeOrNone)
{
  Array<Vector3> positions =
    pts({ Vector3(0, 0, 0), Vector3(1, 0, 0), Vector3(0, 1, 0) });
  EXPECT_FALSE(AtomTuple(0, 3).measure(positions).has_value());
  EXPECT_FALSE(AtomTuple(0, 1, 3).measure(positions).has_value());
  EXPECT_FALSE(AtomTuple(0, 1, 2, 3).measure(positions).has_value());
  EXPECT_FALSE(
    AtomTuple::outOfPlane(0, 1, 2, 3).measure(positions).has_value());
  EXPECT_FALSE(AtomTuple(0, 1).measure(Array<Vector3>()).has_value());
  EXPECT_FALSE(AtomTuple().measure(positions).has_value());
  EXPECT_FALSE(AtomTuple(1, 1).measure(positions).has_value());
}

namespace {
// UnitCell takes its angles in radians.
UnitCell cubicCell()
{
  const Real right = M_PI / 2.0;
  return UnitCell(10, 10, 10, right, right, right);
}

UnitCell triclinicCell()
{
  const Real right = M_PI / 2.0;
  return UnitCell(10, 10, 10, right, right, 75.0 * M_PI / 180.0);
}

Array<Vector3> wrapAll(const Array<Vector3>& positions, const UnitCell& cell)
{
  Array<Vector3> wrapped;
  for (const Vector3& p : positions)
    wrapped.push_back(cell.wrapCartesian(p));
  return wrapped;
}

Array<Vector3> shifted(const Array<Vector3>& positions, const Vector3& offset)
{
  Array<Vector3> result;
  for (const Vector3& p : positions)
    result.push_back(p + offset);
  return result;
}

Array<Vector3> dihedralGeometry(Real sign)
{
  const Real c60 = std::cos(60.0 * M_PI / 180.0);
  const Real s60 = std::sin(60.0 * M_PI / 180.0);
  return pts({ Vector3(1, 0, 0), Vector3(0, 0, 0), Vector3(0, 0, 1),
               Vector3(c60, sign * s60, 1) });
}

void expectImage(const AtomTuple& tuple, const Array<Vector3>& positions,
                 const UnitCell& cell, Real expected)
{
  auto value = tuple.minimumImageMeasure(positions, cell);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, expected, tol);
  value = tuple.reversed().minimumImageMeasure(positions, cell);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, expected, tol);
}
} // namespace

TEST(AtomTupleTest, minimumImageDistance)
{
  UnitCell cell = cubicCell();
  Array<Vector3> positions = pts({ Vector3(0.5, 5, 5), Vector3(9.5, 5, 5) });
  AtomTuple tuple(0, 1);
  EXPECT_NEAR(*tuple.measure(positions), 9.0, tol);
  auto value = tuple.minimumImageMeasure(positions, cell);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, 1.0, tol);
  EXPECT_NEAR(*value, cell.distance(positions[0], positions[1]), tol);
}

TEST(AtomTupleTest, minimumImageAngleAcrossBoundary)
{
  UnitCell cell = cubicCell();
  // a is at (9.5, 5, 5), whose nearest image to b is (-0.5, 5, 5).
  Array<Vector3> positions =
    pts({ Vector3(9.5, 5, 5), Vector3(0.5, 5, 5), Vector3(0.5, 6, 5) });
  expectImage(AtomTuple(0, 1, 2), positions, cell, 90.0);
}

TEST(AtomTupleTest, minimumImageDihedralStraddlingFace)
{
  UnitCell cell = cubicCell();
  for (Real sign : { 1.0, -1.0 }) {
    // wrapCartesian() wraps into [0, 10). Put b at x = 9.8 so that a
    // (x = 10.8) and d (x = 10.3) wrap across the face to x = 0.8 and 0.3.
    Array<Vector3> raw = shifted(dihedralGeometry(sign), Vector3(9.8, 5, 5));
    Array<Vector3> wrapped = wrapAll(raw, cell);
    EXPECT_LT(wrapped[0].x(), 5.0);
    EXPECT_GT(wrapped[1].x(), 5.0);
    expectImage(AtomTuple(0, 1, 2, 3), wrapped, cell, sign * 60.0);
  }
}

TEST(AtomTupleTest, minimumImageOutOfPlaneStraddlingFace)
{
  UnitCell cell = cubicCell();
  // wrapCartesian() wraps into [0, 10). The center sits at x = 9.8 and b
  // (x = 10.8) wraps across the face to x = 0.8.
  Array<Vector3> raw = shifted(pts({ Vector3(0, 0, 0), Vector3(1, 0, 0),
                                     Vector3(0, 1, 0), Vector3(0, 0, 1) }),
                               Vector3(9.8, 5, 5));
  Array<Vector3> wrapped = wrapAll(raw, cell);
  EXPECT_LT(wrapped[1].x(), 5.0);
  EXPECT_GT(wrapped[0].x(), 5.0);
  auto value =
    AtomTuple::outOfPlane(0, 1, 2, 3).minimumImageMeasure(wrapped, cell);
  ASSERT_TRUE(value.has_value());
  EXPECT_NEAR(*value, 90.0, tol);
}

TEST(AtomTupleTest, minimumImageTriclinicDihedral)
{
  UnitCell cell = triclinicCell();
  for (Real sign : { 1.0, -1.0 }) {
    Array<Vector3> raw =
      shifted(dihedralGeometry(sign), Vector3(-0.5, -0.5, 5));
    auto expected = AtomTuple(0, 1, 2, 3).measure(raw);
    ASSERT_TRUE(expected.has_value());
    // b sits just outside the cell, so the atoms wrap to other faces.
    Array<Vector3> wrapped = wrapAll(raw, cell);
    bool moved = false;
    for (size_t i = 0; i < raw.size(); ++i)
      moved = moved || (wrapped[i] - raw[i]).norm() > 0.5;
    EXPECT_TRUE(moved);
    expectImage(AtomTuple(0, 1, 2, 3), wrapped, cell, *expected);
  }
}

TEST(AtomTupleTest, minimumImageMatchesMeasureInsideCell)
{
  UnitCell cell = cubicCell();
  Array<Vector3> positions = shifted(dihedralGeometry(1.0), Vector3(5, 5, 4));
  const AtomTuple tuples[] = { AtomTuple(0, 1), AtomTuple(0, 1, 2),
                               AtomTuple(0, 1, 2, 3),
                               AtomTuple::outOfPlane(1, 0, 2, 3) };
  for (const AtomTuple& tuple : tuples) {
    auto raw = tuple.measure(positions);
    auto image = tuple.minimumImageMeasure(positions, cell);
    ASSERT_TRUE(raw.has_value());
    ASSERT_TRUE(image.has_value());
    EXPECT_NEAR(*image, *raw, tol);
  }
}

TEST(AtomTupleTest, minimumImageRejectsBadInput)
{
  UnitCell cell = cubicCell();
  Array<Vector3> positions = pts(
    { Vector3(1, 1, 1), Vector3(2, 1, 1), Vector3(2, 2, 1), Vector3(2, 2, 2) });
  UnitCell singular;
  singular.setCellMatrix(Avogadro::Matrix3::Zero());
  ASSERT_FALSE(singular.isRegular());
  EXPECT_FALSE(AtomTuple(0, 1).minimumImageMeasure(positions, singular));
  EXPECT_FALSE(AtomTuple(0, 1, 2, 3).minimumImageMeasure(positions, singular));
  EXPECT_FALSE(AtomTuple().minimumImageMeasure(positions, cell));
  EXPECT_FALSE(AtomTuple(1, 1).minimumImageMeasure(positions, cell));
  EXPECT_FALSE(AtomTuple(0, 4).minimumImageMeasure(positions, cell));
  EXPECT_FALSE(AtomTuple(0, 1, 9).minimumImageMeasure(positions, cell));
  EXPECT_FALSE(
    AtomTuple::outOfPlane(0, 1, 2, 4).minimumImageMeasure(positions, cell));
}

TEST(AtomTupleTest, nonFinitePositionsGiveNullopt)
{
  const Real nan = std::numeric_limits<Real>::quiet_NaN();
  UnitCell cell = cubicCell();
  Array<Vector3> positions =
    pts({ Vector3(1, 1, 1), Vector3(2, 1, 1), Vector3(2, 2, 1),
          Vector3(2, 2, 2), Vector3(5, 5, 5) });
  const AtomTuple tuples[] = { AtomTuple(0, 1), AtomTuple(0, 1, 2),
                               AtomTuple(0, 1, 2, 3),
                               AtomTuple::outOfPlane(0, 1, 2, 3) };

  // A NaN in an atom outside the tuples changes nothing.
  Array<Vector3> stray = positions;
  stray[4] = Vector3(nan, nan, nan);
  for (const AtomTuple& tuple : tuples) {
    EXPECT_TRUE(tuple.measure(stray).has_value());
    EXPECT_TRUE(tuple.minimumImageMeasure(stray, cell).has_value());
  }

  // A NaN coordinate in any atom of the tuple gives nullopt.
  for (size_t bad = 0; bad < 4; ++bad) {
    Array<Vector3> corrupt = positions;
    corrupt[bad] = Vector3(1, nan, 1);
    for (const AtomTuple& tuple : tuples) {
      if (bad >= tuple.size())
        continue; // the NaN atom is not part of this tuple
      EXPECT_FALSE(tuple.measure(corrupt).has_value());
      EXPECT_FALSE(tuple.minimumImageMeasure(corrupt, cell).has_value());
    }
  }
}
