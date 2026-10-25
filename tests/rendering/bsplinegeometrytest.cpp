/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include "legacyspline.h"

#include <avogadro/core/vector.h>
#include <avogadro/rendering/bsplinegeometry.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <random>
#include <vector>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Rendering::BSplineGeometry;
using Avogadro::Rendering::ColorNormalVertex;

namespace {

class TestSpline : public BSplineGeometry
{
public:
  using BSplineGeometry::BSplineGeometry;
  Vector3f eval(float t) const
  {
    return computeCurvePoint(t, lines()[0]->points);
  }
  Vector3f segment(size_t k, float f) const
  {
    return computeSegmentPoint(k, f, lines()[0]->points);
  }
};

// A tube whose ring radius encodes the control point passed to
// computeScale() and the position within it.
class ScaleProbe : public BSplineGeometry
{
public:
  ScaleProbe() : BSplineGeometry(false) {}

protected:
  float computeScale(size_t index, float t, float) const override
  {
    return 0.05f + 0.01f * (static_cast<float>(index) + 0.25f * t);
  }
};

size_t colorId(const Vector3ub& c)
{
  return static_cast<size_t>(c[0]) | static_cast<size_t>(c[1]) << 8 |
         static_cast<size_t>(c[2]) << 16;
}

Vector3ub idColor(size_t id)
{
  return Vector3ub(static_cast<unsigned char>(id & 255),
                   static_cast<unsigned char>((id >> 8) & 255),
                   static_cast<unsigned char>((id >> 16) & 255));
}

// alpha helix C-alpha trace: 2.3 A radius, 1.5 A rise, 100 degrees per residue
std::vector<Vector3f> helix(int n)
{
  std::vector<Vector3f> pts;
  for (int i = 0; i < n; ++i) {
    float t = static_cast<float>(i) * 100.0f * 3.14159265f / 180.0f;
    pts.emplace_back(2.3f * std::cos(t), 2.3f * std::sin(t), 1.5f * i);
  }
  return pts;
}

struct Rings
{
  std::vector<Vector3f> centre;
  std::vector<size_t> owner; // from the colour
  std::vector<float> radius;
};

// One entry per ring, in drawing order (a ring is duplicated where the
// colour changes).
Rings rings(const BSplineGeometry& g, size_t sides)
{
  std::vector<ColorNormalVertex> v;
  std::vector<unsigned int> idx;
  g.tessellate(0, v, idx);
  Rings r;
  for (size_t base = 0; base + sides <= v.size(); base += sides) {
    Vector3f c = Vector3f::Zero();
    for (size_t j = 0; j < sides; ++j)
      c += v[base + j].vertex;
    c /= static_cast<float>(sides);
    r.centre.push_back(c);
    r.owner.push_back(colorId(v[base].color));
    r.radius.push_back((v[base].vertex - c).norm());
  }
  return r;
}

struct StepStats
{
  float max = 0.0f, median = 0.0f;
  size_t reversals = 0;
};

StepStats steps(const std::vector<Vector3f>& p)
{
  std::vector<float> d;
  std::vector<Vector3f> s;
  for (size_t i = 1; i < p.size(); ++i) {
    Vector3f step = p[i] - p[i - 1];
    if (step.norm() < 1e-6f)
      continue; // duplicated ring
    d.push_back(step.norm());
    s.push_back(step);
  }
  StepStats r;
  r.max = *std::max_element(d.begin(), d.end());
  std::vector<float> sorted(d);
  std::sort(sorted.begin(), sorted.end());
  r.median = sorted[sorted.size() / 2];
  for (size_t i = 1; i < s.size(); ++i)
    if (s[i].dot(s[i - 1]) < 0.0f)
      ++r.reversals;
  return r;
}

// Control point nearest to p, and by how much `owner` is further than that.
float excess(const Vector3f& p, size_t owner, const std::vector<Vector3f>& pts,
             size_t* nearest = nullptr)
{
  size_t best = 0;
  for (size_t i = 1; i < pts.size(); ++i)
    if ((pts[i] - p).squaredNorm() < (pts[best] - p).squaredNorm())
      best = i;
  if (nearest)
    *nearest = best;
  return (pts[owner] - p).norm() - (pts[best] - p).norm();
}

void fill(BSplineGeometry& g, const std::vector<Vector3f>& pts, float radius)
{
  for (size_t i = 0; i < pts.size(); ++i)
    g.addPoint(pts[i], idColor(i), radius, 0, i);
}

// independent global uniform quadratic B-spline: Cox-de Boor with knots at
// the integers, evaluated at x = segment + 2 + f
Vector3f referenceSegmentPoint(size_t k, float f,
                               const std::vector<Vector3f>& pts)
{
  Vector3f q = Vector3f::Zero();
  const float x = static_cast<float>(k) + 2.0f + f;
  for (size_t i = 0; i < pts.size(); ++i)
    q += pts[i] * LegacySpline::basis(static_cast<float>(i), 3.0f, x, 1.0f);
  return q;
}

} // namespace

TEST(BSplineGeometryTest, matchesUniformBasisDefinition)
{
  std::mt19937 rng(12345);
  std::uniform_real_distribution<float> coord(-20.0f, 20.0f);
  float maxDiff = 0.0f;
  for (int n = 3; n <= 40; ++n) {
    TestSpline spline;
    std::vector<Vector3f> pts;
    for (int i = 0; i < n; ++i) {
      pts.emplace_back(coord(rng), coord(rng), coord(rng));
      spline.addPoint(pts.back(), Vector3ub(1, 2, 3), 0.1f, 0,
                      static_cast<size_t>(i));
    }
    for (size_t k = 0; k + 2 < static_cast<size_t>(n); ++k) {
      for (int j = 0; j < 20; ++j) {
        const float f = static_cast<float>(j) / 20.0f;
        Vector3f a = spline.segment(k, f);
        Vector3f b = referenceSegmentPoint(k, f, pts);
        maxDiff = std::max(maxDiff, (a - b).cwiseAbs().maxCoeff());
        // the t in [0, 1] form lands on the same curve
        const float t = (static_cast<float>(k) + f) / static_cast<float>(n - 2);
        Vector3f c = spline.eval(t);
        maxDiff = std::max(maxDiff, (a - c).cwiseAbs().maxCoeff());
      }
    }
  }
  std::printf("BSpline max abs difference: %g\n", maxDiff);
  EXPECT_LT(maxDiff, 1e-3f);
}

TEST(BSplineGeometryTest, knotsAreChordMidpointsAndCurveIsC1)
{
  TestSpline spline;
  std::vector<Vector3f> pts = helix(12);
  for (size_t i = 0; i < pts.size(); ++i)
    spline.addPoint(pts[i], Vector3ub(1, 2, 3), 0.1f, 0, i);
  for (size_t k = 0; k + 3 < pts.size(); ++k) {
    EXPECT_LT((spline.segment(k, 0.0f) - 0.5f * (pts[k] + pts[k + 1])).norm(),
              1e-5f);
    // end of segment k is the start of segment k + 1, with the same tangent
    EXPECT_LT((spline.segment(k, 1.0f) - spline.segment(k + 1, 0.0f)).norm(),
              1e-5f);
    const float h = 1e-2f;
    Vector3f d1 = (spline.segment(k, 1.0f) - spline.segment(k, 1.0f - h)) / h;
    Vector3f d2 = (spline.segment(k + 1, h) - spline.segment(k + 1, 0.0f)) / h;
    // one-sided differences differ by O(h * curvature)
    EXPECT_LT((d1 - d2).norm(), 0.1f * d1.norm());
  }
}

TEST(BSplineGeometryTest, fewPointsAreSafe)
{
  for (int n = 0; n <= 4; ++n) {
    TestSpline spline;
    for (int i = 0; i < n; ++i)
      spline.addPoint(Vector3f(i, 0, 0), Vector3ub(1, 2, 3), 0.1f, 0, i);
    if (n == 0)
      continue;
    Vector3f p = spline.eval(0.5f);
    EXPECT_TRUE(p.allFinite());
    EXPECT_TRUE(spline.eval(-1.0f).allFinite());
    EXPECT_TRUE(spline.eval(2.0f).allFinite());
  }
}

TEST(BSplineGeometryTest, helixIsContinuous)
{
  const auto pts = helix(60);
  BSplineGeometry g(false);
  fill(g, pts, 0.1f);
  const Rings r = rings(g, 12);
  ASSERT_GT(r.centre.size(), 500u);
  const StepStats now = steps(r.centre);

  std::vector<Vector3f> legacy;
  for (const auto& s : LegacySpline::samples(pts))
    legacy.push_back(s.pos);
  const StepStats old = steps(legacy);
  std::printf("helix step max/median: old %.3f/%.3f = %.2f (%zu reversals), "
              "new %.3f/%.3f = %.2f (%zu reversals)\n",
              old.max, old.median, old.max / old.median, old.reversals, now.max,
              now.median, now.max / now.median, now.reversals);
  EXPECT_LT(now.max, 1.25f * now.median);
  EXPECT_EQ(now.reversals, 0u);
  // the test is sensitive to the old jumps
  EXPECT_GT(old.max, 1.5f * old.median);
}

TEST(BSplineGeometryTest, colourAndScaleBelongToTheNearestControlPoint)
{
  const auto pts = helix(60);
  ScaleProbe g;
  fill(g, pts, 0.1f);
  const Rings r = rings(g, 12);
  ASSERT_GT(r.centre.size(), 500u);
  float worst = 0.0f;
  size_t exact = 0, previousOwner = 0, scaleMismatch = 0;
  for (size_t i = 0; i < r.centre.size(); ++i) {
    const size_t owner = r.owner[i];
    ASSERT_LT(owner, pts.size());
    EXPECT_GE(owner, previousOwner) << "owners must not go backwards";
    previousOwner = owner;
    size_t nearest;
    const float e = excess(r.centre[i], owner, pts, &nearest);
    worst = std::max(worst, e);
    exact += nearest == owner;
    // the width carries the same control point, except at the first ring
    // of a stretch, which the strip before it colours with the previous one
    const float index = (r.radius[i] - 0.05f) / 0.01f;
    const size_t scaleOwner = static_cast<size_t>(index + 1e-3f);
    if (scaleOwner != owner && scaleOwner != owner + 1)
      ++scaleMismatch;
  }
  std::printf("new: %zu of %zu rings have their owner as nearest control "
              "point, worst excess distance %.3f A\n",
              exact, r.centre.size(), worst);
  EXPECT_LT(worst, 0.25f);
  EXPECT_EQ(scaleMismatch, 0u);
  EXPECT_GT(exact, r.centre.size() * 9 / 10);

  // the old code coloured by a control point about one residue behind
  float oldWorst = 0.0f;
  size_t oldExact = 0;
  const auto legacy = LegacySpline::samples(pts);
  for (const auto& s : legacy) {
    size_t nearest;
    // the old colour is that of the plugin's "previous" convention, so the
    // stretch is the residue of the *geometry* when colour index - 1 is
    // nearest; compare against the colour index itself
    oldWorst = std::max(oldWorst, excess(s.pos, s.colorIndex, pts, &nearest));
    oldExact += nearest == s.colorIndex;
  }
  std::printf("old: %zu of %zu samples have their colour's control point as "
              "nearest, worst excess distance %.3f A\n",
              oldExact, legacy.size(), oldWorst);
}

TEST(BSplineGeometryTest, honoursSegmentAndSideCounts)
{
  const auto pts = helix(30);
  for (size_t segments : { 1u, 6u, 15u }) {
    for (size_t sides : { 3u, 8u, 12u }) {
      BSplineGeometry g(false);
      // one colour, so no ring is duplicated
      for (size_t i = 0; i < pts.size(); ++i)
        g.addPoint(pts[i], Vector3ub(9, 9, 9), 0.1f, 0, i);
      g.setSegmentsPerResidue(segments);
      g.setSides(sides);
      std::vector<ColorNormalVertex> v;
      std::vector<unsigned int> idx;
      g.tessellate(0, v, idx);
      // 27 segments are drawn (the last is dropped); the first sample only
      // seeds the first tangent
      const size_t frames = 27 * segments;
      EXPECT_EQ(v.size(), frames * sides);
      EXPECT_EQ(idx.size(), (frames - 1) * sides * 6);
      for (unsigned int i : idx)
        ASSERT_LT(i, v.size());
    }
  }
  // the defaults are unchanged
  BSplineGeometry g(false);
  EXPECT_EQ(g.segmentsFor(false), 15u);
  EXPECT_EQ(g.segmentsFor(true), 20u);
}
