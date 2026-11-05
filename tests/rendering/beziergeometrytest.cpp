/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// The rope: one Bezier curve over all of a chain's control points, drawn from
// the first to the last, with each stretch coloured by the control point it
// is centred on.

#include <gtest/gtest.h>

#include "curvetesthelpers.h"

#include <avogadro/core/vector.h>
#include <avogadro/rendering/beziergeometry.h>

#include <algorithm>
#include <cmath>
#include <vector>

using namespace CurveTest;
using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Rendering::BezierGeometry;
using Avogadro::Rendering::ColorNormalVertex;

namespace {

class TestRope : public BezierGeometry
{
public:
  Vector3f eval(float t) const
  {
    return computeCurvePoint(t, lines()[0]->points);
  }
};

void fill(BezierGeometry& g, const std::vector<Vector3f>& pts)
{
  for (size_t i = 0; i < pts.size(); ++i)
    g.addPoint(pts[i], idColor(i), 0.1f, 0, i);
}

Rings rings(const BezierGeometry& g)
{
  std::vector<ColorNormalVertex> v;
  std::vector<unsigned int> idx;
  g.tessellate(0, v, idx);
  return ringsOf(v, 12);
}

} // namespace

TEST(BezierGeometryTest, isTheBezierCurveOverAllControlPoints)
{
  float maxDiff = 0.0f;
  for (int n = 2; n <= 30; ++n) {
    TestRope rope;
    const auto pts = wobble(n);
    fill(rope, pts);
    for (int s = 1; s < 50; ++s) {
      const double t = s / 50.0;
      // Bernstein polynomials, in double
      double basis = std::pow(1.0 - t, n - 1);
      Eigen::Vector3d q = Eigen::Vector3d::Zero();
      for (int k = 0; k < n; ++k) {
        q += basis * pts[k].cast<double>();
        basis *= (n - 1 - k) / double(k + 1) * t / (1.0 - t);
      }
      const Eigen::Vector3d p = rope.eval(static_cast<float>(t)).cast<double>();
      maxDiff =
        std::max(maxDiff, static_cast<float>((p - q).cwiseAbs().maxCoeff()));
    }
    EXPECT_LT((rope.eval(0.0f) - pts.front()).norm(), 1e-6f);
    EXPECT_LT((rope.eval(1.0f) - pts.back()).norm(), 1e-6f);
  }
  EXPECT_LT(maxDiff, 2e-3f);
}

TEST(BezierGeometryTest, straightChainShowsWhichResidueEachStretchIsCentredOn)
{
  // On a straight chain with unit spacing the Bezier point is at the centre
  // index, so a stretch coloured k lies within half a residue of k.
  for (int n : { 2, 3, 5, 12, 60 }) {
    BezierGeometry g;
    std::vector<Vector3f> pts;
    for (int i = 0; i < n; ++i)
      pts.emplace_back(3.8f * i, 0.0f, 0.0f);
    fill(g, pts);
    const Rings r = rings(g);
    ASSERT_GT(r.centre.size(), 10u);
    EXPECT_LT(r.centre.front().norm(), 1e-3f);
    EXPECT_LT((r.centre.back() - pts.back()).norm(), 1e-3f);
    EXPECT_EQ(r.owner.front(), 0u);
    EXPECT_EQ(r.owner.back(), static_cast<size_t>(n - 1));
    std::vector<size_t> perResidue(n, 0);
    size_t previous = 0;
    for (size_t i = 0; i < r.centre.size(); ++i) {
      const float index = r.centre[i].x() / 3.8f;
      const size_t k = r.owner[i];
      EXPECT_GE(k, previous);
      previous = k;
      ++perResidue[k];
      EXPECT_LE(std::abs(index - static_cast<float>(k)), 0.5f + 1e-3f)
        << "n=" << n << " ring " << i;
      if (i > 0)
        EXPECT_GE(r.centre[i].x(), r.centre[i - 1].x() - 1e-4f);
    }
    for (int k = 0; k < n; ++k)
      EXPECT_GE(perResidue[k], 7u) << "residue " << k << " has a stretch";
  }
}

TEST(BezierGeometryTest, continuousAndReachesTheEnds)
{
  for (const auto& pts : { wobble(40), helix(60) }) {
    BezierGeometry g;
    fill(g, pts);
    checkChain(pts, rings(g));
  }
}

TEST(BezierGeometryTest, shortChains)
{
  for (int n = 0; n <= 3; ++n) {
    BezierGeometry g;
    fill(g, wobble(n));
    std::vector<ColorNormalVertex> v;
    std::vector<unsigned int> idx;
    g.tessellate(0, v, idx);
    if (n < 2) {
      EXPECT_TRUE(v.empty());
      continue;
    }
    EXPECT_FALSE(idx.empty());
    EXPECT_TRUE(allFinite(v));
    for (unsigned int i : idx)
      ASSERT_LT(i, v.size());
  }
}

TEST(BezierGeometryTest, longChainsStayFinite)
{
  // the iteration must not underflow into NaN for a whole capsid protein
  for (int n : { 100, 300, 1000 }) {
    BezierGeometry g;
    fill(g, helix(n));
    const Rings r = rings(g);
    ASSERT_GT(r.centre.size(), 100u);
    for (const auto& c : r.centre)
      ASSERT_TRUE(c.allFinite()) << n;
    checkChain(helix(n), r);
  }
}
