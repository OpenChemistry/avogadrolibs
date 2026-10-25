/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include "curvetesthelpers.h"

#include <cartoondetail.h>

#include <avogadro/core/vector.h>
#include <avogadro/rendering/bsplinegeometry.h>
#include <avogadro/rendering/cartoongeometry.h>

#include <cmath>
#include <vector>

using namespace CurveTest;
using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Core::Residue;
using Avogadro::QtPlugins::CartoonDetail;
using Avogadro::QtPlugins::CartoonResidueCounts;
using Avogadro::Rendering::BSplineGeometry;
using Avogadro::Rendering::Cartoon;
using Avogadro::Rendering::ColorNormalVertex;
using Avogadro::Rendering::CurveGeometry;
using namespace Avogadro::QtPlugins;

namespace {

CartoonResidueCounts cartoons(size_t residues)
{
  CartoonResidueCounts c;
  c.cartoon = residues;
  return c;
}

// A tube of the helix, one colour so that no ring is repeated.
void addHelix(BSplineGeometry& g, int n)
{
  const auto pts = helix(n);
  for (int i = 0; i < n; ++i)
    g.addPoint(pts[i], Vector3ub(5, 6, 7), 0.2f, 0, static_cast<size_t>(i));
}

// An extended chain, coloured alike.
void addStrand(CurveGeometry& g, int n, float radius)
{
  for (int i = 0; i < n; ++i)
    g.addPoint(Vector3f(3.3f * i, std::sin(0.5f * i), 0), Vector3ub(5, 6, 7),
               radius, 0, i);
}

size_t vertexCount(const CurveGeometry& g, size_t* indexCount = nullptr)
{
  std::vector<ColorNormalVertex> v;
  std::vector<unsigned int> idx;
  g.tessellate(0, v, idx);
  if (indexCount)
    *indexCount = idx.size();
  return v.size();
}

} // namespace

TEST(CartoonDetailTest, firstLevelIsTheBuiltInDetail)
{
  EXPECT_EQ(kCartoonDetailLevels[0].segments, CurveGeometry::kDefaultSegments);
  EXPECT_EQ(kCartoonDetailLevels[0].sides, Cartoon::kDefaultSides);
  EXPECT_EQ(tubeSides(kCartoonDetailLevels[0]),
            CurveGeometry::kDefaultTubeSides);
  EXPECT_EQ(flatSegments(kCartoonDetailLevels[0]),
            CurveGeometry::flatSegmentsFor(CurveGeometry::kDefaultSegments));
  // the values themselves, which drawn proteins depend on
  EXPECT_EQ(CurveGeometry::kDefaultSegments, 15u);
  EXPECT_EQ(CurveGeometry::kDefaultTubeSides, 12u);
  EXPECT_EQ(Cartoon::kDefaultSides, 20u);
  EXPECT_EQ(CurveGeometry::flatSegmentsFor(15), 20u);
}

TEST(CartoonDetailTest, levelsAreOrderedAndTubesStayAtLeastSix)
{
  for (size_t i = 1; i < kCartoonDetailLevels.size(); ++i) {
    EXPECT_LE(kCartoonDetailLevels[i].segments,
              kCartoonDetailLevels[i - 1].segments);
    EXPECT_LE(kCartoonDetailLevels[i].sides, kCartoonDetailLevels[i - 1].sides);
  }
  for (const auto& level : kCartoonDetailLevels) {
    EXPECT_GE(tubeSides(level), 6u);
    EXPECT_GE(level.sides, 3u);
    EXPECT_GE(level.segments, 1u);
  }
}

TEST(CartoonDetailTest, picksTheFirstLevelThatFits)
{
  // 300, 192, 120, 80 and 48 ring vertices per cartoon residue
  EXPECT_EQ(cartoonRingVertices(cartoons(1), kCartoonDetailLevels[0]), 300u);
  EXPECT_EQ(cartoonRingVertices(cartoons(1), kCartoonDetailLevels[1]), 192u);
  EXPECT_EQ(cartoonRingVertices(cartoons(1), kCartoonDetailLevels[2]), 120u);
  EXPECT_EQ(cartoonRingVertices(cartoons(1), kCartoonDetailLevels[3]), 80u);
  EXPECT_EQ(cartoonRingVertices(cartoons(1), kCartoonDetailLevels[4]), 48u);

  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(0)), 0u);
  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(46)), 0u); // 1CRN
  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(16666)), 0u);
  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(16667)), 1u);
  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(26041)), 1u);
  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(26042)), 2u);
  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(41666)), 2u);
  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(41667)), 3u);
  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(62500)), 3u);
  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(62501)), 4u);
  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(104166)), 4u);
  // past the budget even at the floor, the floor is still used
  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(104167)), 4u);
  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(129120)), 4u); // 9MB0
  EXPECT_EQ(chooseCartoonDetailLevel(cartoons(100000000)), 4u);
}

TEST(CartoonDetailTest, neverFinerForMoreResidues)
{
  size_t previous = 0;
  for (size_t residues = 0; residues < 200000; residues += 37) {
    const size_t level = chooseCartoonDetailLevel(cartoons(residues));
    EXPECT_GE(level, previous);
    previous = level;
    if (level + 1 < kCartoonDetailLevels.size()) {
      EXPECT_LE(
        cartoonRingVertices(cartoons(residues), kCartoonDetailLevels[level]),
        kCartoonRingVertexBudget);
    }
  }
}

TEST(CartoonDetailTest, allStylesCountTowardsTheBudget)
{
  CartoonResidueCounts c;
  c.cartoon = 10000; // 3.0 M at the first level
  EXPECT_EQ(chooseCartoonDetailLevel(c), 0u);
  c.tube = 10000; // + 10000 x 15 x 12 = 1.8 M
  EXPECT_EQ(chooseCartoonDetailLevel(c), 0u);
  c.ribbon = 10000; // + 10000 x 20 x 2 = 0.4 M
  EXPECT_EQ(cartoonRingVertices(c, kCartoonDetailLevels[0]), 5200000u);
  EXPECT_EQ(chooseCartoonDetailLevel(c), 1u);
  // an explicit budget
  EXPECT_EQ(chooseCartoonDetailLevel(c, 1000000000), 0u);
  EXPECT_EQ(chooseCartoonDetailLevel(c, 0), 4u);
}

TEST(CartoonDetailTest, everyStyleIsCountedWhereItsGeometryIs)
{
  CartoonResidueCounts c;
  c.add(CartoonStyle::Trace, 1);
  c.add(CartoonStyle::Tube, 2);
  c.add(CartoonStyle::Rope, 4); // a rope is a tube of the same sides
  c.add(CartoonStyle::Ribbon, 8);
  c.add(CartoonStyle::SimpleCartoon, 16);
  c.add(CartoonStyle::Cartoon, 32);
  EXPECT_EQ(c.trace, 1u);
  EXPECT_EQ(c.tube, 6u);
  EXPECT_EQ(c.ribbon, 8u);
  EXPECT_EQ(c.cartoon, 48u);

  // a rope alone fits at full detail where a cartoon of the same residues
  // does not, and both together drop a level
  CartoonResidueCounts rope, cartoon, both;
  rope.add(CartoonStyle::Rope, 23220);
  cartoon.add(CartoonStyle::Cartoon, 23220);
  both.add(CartoonStyle::Rope, 23220);
  both.add(CartoonStyle::Cartoon, 23220);
  EXPECT_EQ(chooseCartoonDetailLevel(rope), 0u);
  EXPECT_EQ(chooseCartoonDetailLevel(cartoon), 1u);
  EXPECT_GT(chooseCartoonDetailLevel(both), chooseCartoonDetailLevel(cartoon));
}

TEST(CartoonDetailTest, applySetsTheDetailOnACurve)
{
  const CartoonDetail& level = kCartoonDetailLevels[2];
  BSplineGeometry tube(false);
  level.apply(tube, true);
  EXPECT_EQ(tube.segmentsPerResidue(), level.segments);
  EXPECT_EQ(tube.sides(), tubeSides(level));
  Cartoon cartoon;
  level.apply(cartoon, false);
  EXPECT_EQ(cartoon.segmentsPerResidue(), level.segments);
  EXPECT_EQ(cartoon.sides(), level.sides);
}

TEST(CartoonDetailTest, geometryCountsMatchTheAccounting)
{
  // the plugin's ring vertex arithmetic must agree with what is tessellated:
  // one spline segment per residue, and one ring more than segment samples
  const int n = 40;
  const size_t drawn = n;
  for (const auto& level : kCartoonDetailLevels) {
    Cartoon cartoon(0.1f, 0.5f);
    addStrand(cartoon, n, 0.5f);
    cartoon.setSegmentsPerResidue(level.segments);
    cartoon.setSides(level.sides);
    EXPECT_EQ(vertexCount(cartoon), (drawn * level.segments + 1) * level.sides);

    BSplineGeometry tube(false);
    addHelix(tube, n);
    tube.setSegmentsPerResidue(level.segments);
    tube.setSides(tubeSides(level));
    EXPECT_EQ(vertexCount(tube),
              (drawn * level.segments + 1) * tubeSides(level));

    // flat ribbon (negative radius, as the plugin draws it): two vertices a
    // ring whatever the sides
    Cartoon flat(-0.1f, -0.5f);
    addStrand(flat, n, -0.75f);
    flat.setSegmentsPerResidue(level.segments);
    flat.setSides(level.sides);
    EXPECT_EQ(vertexCount(flat), (drawn * flatSegments(level) + 1) * 2);
    EXPECT_EQ(flat.segmentsFor(true), flatSegments(level));

    // flat line (trace): one vertex a sample, and no triangles
    BSplineGeometry trace;
    addStrand(trace, n, -0.15f);
    trace.setSegmentsPerResidue(level.segments);
    size_t indices = 1;
    EXPECT_EQ(vertexCount(trace, &indices), drawn * flatSegments(level) + 1);
    EXPECT_EQ(indices, 0u);
  }
}

TEST(CartoonDetailTest, defaultsLeaveOtherUsersUnchanged)
{
  // no setting == the built-in values
  std::vector<ColorNormalVertex> a, b;
  std::vector<unsigned int> ia, ib;
  BSplineGeometry plain(false), explicitDefault(false);
  addHelix(plain, 30);
  addHelix(explicitDefault, 30);
  explicitDefault.setSegmentsPerResidue(CurveGeometry::kDefaultSegments);
  explicitDefault.setSides(CurveGeometry::kDefaultTubeSides);
  plain.tessellate(0, a, ia);
  explicitDefault.tessellate(0, b, ib);
  ASSERT_EQ(a.size(), b.size());
  ASSERT_EQ(ia, ib);
  EXPECT_EQ(a.size(),
            CurveGeometry::ringVertices(30, CurveGeometry::kDefaultSegments,
                                        CurveGeometry::kDefaultTubeSides) +
              CurveGeometry::kDefaultTubeSides);
  for (size_t i = 0; i < a.size(); ++i)
    ASSERT_EQ(a[i].vertex, b[i].vertex);
}
