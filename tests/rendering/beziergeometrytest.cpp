/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// The rope: one Bezier curve over all of a chain's control points, drawn from
// the first to the last, with each stretch coloured by the control point it
// is centred on.

#include <gtest/gtest.h>

#include <avogadro/core/vector.h>
#include <avogadro/rendering/beziergeometry.h>

#include <algorithm>
#include <cmath>
#include <vector>

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

Vector3ub idColor(size_t id)
{
  return Vector3ub(static_cast<unsigned char>(id & 255),
                   static_cast<unsigned char>((id >> 8) & 255), 0);
}

size_t colorId(const Vector3ub& c)
{
  return static_cast<size_t>(c[0]) | static_cast<size_t>(c[1]) << 8;
}

void fill(BezierGeometry& g, const std::vector<Vector3f>& pts)
{
  for (size_t i = 0; i < pts.size(); ++i)
    g.addPoint(pts[i], idColor(i), 0.1f, 0, i);
}

struct Rings
{
  std::vector<Vector3f> centre;
  std::vector<size_t> owner;
};

Rings rings(const BezierGeometry& g)
{
  std::vector<ColorNormalVertex> v;
  std::vector<unsigned int> idx;
  g.tessellate(0, v, idx);
  Rings r;
  for (size_t base = 0; base + 12 <= v.size(); base += 12) {
    Vector3f c = Vector3f::Zero();
    for (size_t j = 0; j < 12; ++j)
      c += v[base + j].vertex / 12.0f;
    r.centre.push_back(c);
    r.owner.push_back(colorId(v[base].color));
  }
  return r;
}

std::vector<Vector3f> wobble(int n)
{
  std::vector<Vector3f> pts;
  for (int i = 0; i < n; ++i)
    pts.emplace_back(3.5f * i, 1.5f * std::sin(0.9f * i), 1.2f * std::cos(i));
  return pts;
}

std::vector<Vector3f> helix(int n)
{
  std::vector<Vector3f> pts;
  for (int i = 0; i < n; ++i) {
    float t = static_cast<float>(i) * 100.0f * 3.14159265f / 180.0f;
    pts.emplace_back(2.3f * std::cos(t), 2.3f * std::sin(t), 1.5f * i);
  }
  return pts;
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
    std::vector<size_t> rings(n, 0);
    size_t previous = 0;
    for (size_t i = 0; i < r.centre.size(); ++i) {
      const float index = r.centre[i].x() / 3.8f;
      const size_t k = r.owner[i];
      EXPECT_GE(k, previous);
      previous = k;
      ++rings[k];
      EXPECT_LE(std::abs(index - static_cast<float>(k)), 0.5f + 1e-3f)
        << "n=" << n << " ring " << i;
      if (i > 0)
        EXPECT_GE(r.centre[i].x(), r.centre[i - 1].x() - 1e-4f);
    }
    for (int k = 0; k < n; ++k)
      EXPECT_GE(rings[k], 7u) << "residue " << k << " has a stretch";
  }
}

TEST(BezierGeometryTest, continuousAndReachesTheEnds)
{
  for (const auto& pts : { wobble(40), helix(60) }) {
    BezierGeometry g;
    fill(g, pts);
    const Rings r = rings(g);
    EXPECT_LT((r.centre.front() - pts.front()).norm(), 1e-3f);
    EXPECT_LT((r.centre.back() - pts.back()).norm(), 1e-3f);
    float maxChord = 0.0f, maxStep = 0.0f;
    for (size_t i = 1; i < pts.size(); ++i)
      maxChord = std::max(maxChord, (pts[i] - pts[i - 1]).norm());
    Vector3f previous = Vector3f::Zero();
    size_t reversals = 0;
    for (size_t i = 1; i < r.centre.size(); ++i) {
      Vector3f s = r.centre[i] - r.centre[i - 1];
      if (s.norm() < 1e-6f)
        continue;
      maxStep = std::max(maxStep, s.norm());
      if (s.dot(previous) < 0.0f)
        ++reversals;
      previous = s;
    }
    EXPECT_LE(maxStep, maxChord / 15.0f * (1.0f + 1e-3f));
    EXPECT_EQ(reversals, 0u);
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
    for (const auto& x : v)
      ASSERT_TRUE(x.vertex.allFinite() && x.normal.allFinite());
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
    EXPECT_LT((r.centre.front() - helix(n).front()).norm(), 1e-3f);
    EXPECT_LT((r.centre.back() - helix(n).back()).norm(), 1e-3f);
  }
}
