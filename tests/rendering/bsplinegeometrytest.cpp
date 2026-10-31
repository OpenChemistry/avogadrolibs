/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include "curvetesthelpers.h"
#include "coxdeboor.h"

#include <avogadro/core/vector.h>
#include <avogadro/rendering/bsplinegeometry.h>
#include <avogadro/rendering/cartoongeometry.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <initializer_list>
#include <random>
#include <vector>

using namespace CurveTest;
using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Core::Residue;
using Avogadro::Rendering::BSplineGeometry;
using Avogadro::Rendering::Cartoon;
using Avogadro::Rendering::ColorNormalVertex;
using Avogadro::Rendering::CurveGeometry;

namespace {

class TestSpline : public BSplineGeometry
{
public:
  using BSplineGeometry::BSplineGeometry;
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

// One entry per ring of a 12-sided tube.
Rings rings(const BSplineGeometry& g)
{
  std::vector<ColorNormalVertex> v;
  std::vector<unsigned int> idx;
  g.tessellate(0, v, idx);
  return ringsOf(v, 12);
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

// independent uniform quadratic B-spline: Cox-de Boor with knots at the
// integers over the control points with both ends doubled, evaluated at
// x = segment + 2 + f
Vector3f referenceSegmentPoint(size_t k, float f,
                               const std::vector<Vector3f>& pts)
{
  std::vector<Vector3f> padded;
  padded.push_back(pts.front());
  padded.insert(padded.end(), pts.begin(), pts.end());
  padded.push_back(pts.back());
  Vector3f q = Vector3f::Zero();
  const float x = static_cast<float>(k) + 2.0f + f;
  for (size_t i = 0; i < padded.size(); ++i)
    q += padded[i] * coxDeBoor(static_cast<float>(i), 3.0f, x, 1.0f);
  return q;
}

} // namespace

TEST(BSplineGeometryTest, matchesUniformBasisDefinition)
{
  std::mt19937 rng(12345);
  std::uniform_real_distribution<float> coord(-20.0f, 20.0f);
  float maxDiff = 0.0f;
  for (int n = 2; n <= 40; ++n) {
    TestSpline spline;
    std::vector<Vector3f> pts;
    for (int i = 0; i < n; ++i) {
      pts.emplace_back(coord(rng), coord(rng), coord(rng));
      spline.addPoint(pts.back(), Vector3ub(1, 2, 3), 0.1f, 0,
                      static_cast<size_t>(i));
    }
    for (size_t k = 0; k < static_cast<size_t>(n); ++k) {
      for (int j = 0; j < 20; ++j) {
        const float f = static_cast<float>(j) / 20.0f;
        Vector3f a = spline.segment(k, f);
        Vector3f b = referenceSegmentPoint(k, f, pts);
        maxDiff = std::max(maxDiff, (a - b).cwiseAbs().maxCoeff());
      }
    }
  }
  std::printf("BSpline max abs difference: %g\n", maxDiff);
  EXPECT_LT(maxDiff, 1e-3f);
}

TEST(BSplineGeometryTest, endsAtTheEndPointsAndIsC1)
{
  TestSpline spline;
  std::vector<Vector3f> pts = helix(12);
  for (size_t i = 0; i < pts.size(); ++i)
    spline.addPoint(pts[i], Vector3ub(1, 2, 3), 0.1f, 0, i);
  const size_t n = pts.size();
  EXPECT_LT((spline.segment(0, 0.0f) - pts.front()).norm(), 1e-5f);
  EXPECT_LT((spline.segment(n - 1, 1.0f) - pts.back()).norm(), 1e-5f);
  // the first segment leaves P0 towards P1
  Vector3f d = spline.segment(0, 0.2f) - pts[0];
  EXPECT_GT(d.normalized().dot((pts[1] - pts[0]).normalized()), 0.999f);
  for (size_t k = 1; k + 1 < n; ++k)
    EXPECT_LT((spline.segment(k, 0.0f) - 0.5f * (pts[k - 1] + pts[k])).norm(),
              1e-5f);
  for (size_t k = 0; k + 1 < n; ++k) {
    // end of segment k is the start of segment k + 1, with the same tangent
    EXPECT_LT((spline.segment(k, 1.0f) - spline.segment(k + 1, 0.0f)).norm(),
              1e-5f);
    if (k == 0)
      continue; // the speed at P0 itself is zero
    const float h = 1e-2f;
    Vector3f d1 = (spline.segment(k, 1.0f) - spline.segment(k, 1.0f - h)) / h;
    Vector3f d2 = (spline.segment(k + 1, h) - spline.segment(k + 1, 0.0f)) / h;
    // one-sided differences differ by O(h * curvature)
    EXPECT_LT((d1 - d2).norm(), 0.1f * d1.norm());
  }
}

TEST(BSplineGeometryTest, fewPointsAreSafe)
{
  for (int n = 1; n <= 4; ++n) {
    TestSpline spline;
    for (int i = 0; i < n; ++i)
      spline.addPoint(Vector3f(i, 0, 0), Vector3ub(1, 2, 3), 0.1f, 0, i);
    for (size_t k = 0; k < static_cast<size_t>(n) + 2; ++k)
      for (float f : { 0.0f, 0.5f, 1.0f })
        EXPECT_TRUE(spline.segment(k, f).allFinite());
  }
}

TEST(BSplineGeometryTest, helixIsContinuous)
{
  const auto pts = helix(60);
  BSplineGeometry g(false);
  fill(g, pts, 0.1f);
  const Rings r = rings(g);
  ASSERT_GT(r.centre.size(), 500u);
  checkChain(pts, r);
}

TEST(BSplineGeometryTest, colourAndScaleBelongToTheNearestControlPoint)
{
  const auto pts = helix(60);
  ScaleProbe g;
  fill(g, pts, 0.1f);
  const Rings r = rings(g);
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
      // one segment per control point, and a frame at every sample
      const size_t frames = 30 * segments + 1;
      EXPECT_EQ(v.size(), frames * sides);
      EXPECT_EQ(idx.size(), (frames - 1) * sides * 6);
      for (unsigned int i : idx)
        ASSERT_LT(i, v.size());
    }
  }
  // the defaults are unchanged
  BSplineGeometry g(false);
  EXPECT_EQ(g.segmentsFor(false), CurveGeometry::kDefaultSegments);
  EXPECT_EQ(g.segmentsFor(true),
            CurveGeometry::flatSegmentsFor(CurveGeometry::kDefaultSegments));
}

namespace {

using SS = Residue::SecondaryStructure;

float meanDistanceToRing(const std::vector<ColorNormalVertex>& v, size_t first,
                         size_t count, const Vector3f& p)
{
  Vector3f c = Vector3f::Zero();
  for (size_t i = 0; i < count; ++i)
    c += v[first + i].vertex;
  return (c / static_cast<float>(count) - p).norm();
}

// The first and last ring (ringSize vertices each) of a tessellated chain are
// centred on its end points.
void expectReachesTheEnds(const std::vector<ColorNormalVertex>& v,
                          size_t ringSize, const std::vector<Vector3f>& pts,
                          float tolerance)
{
  ASSERT_FALSE(v.empty());
  EXPECT_LT(meanDistanceToRing(v, 0, ringSize, pts.front()), tolerance);
  EXPECT_LT(meanDistanceToRing(v, v.size() - ringSize, ringSize, pts.back()),
            tolerance);
}

} // namespace

TEST(BSplineGeometryTest, everyStyleStartsAndEndsAtTheTermini)
{
  for (int n : { 2, 3, 4, 5, 9, 40 }) {
    SCOPED_TRACE(n);
    const auto pts = wobble(n);
    std::vector<ColorNormalVertex> v;
    std::vector<unsigned int> idx;
    {
      BSplineGeometry tube(false);
      fill(tube, pts, 0.1f);
      tube.tessellate(0, v, idx);
      expectReachesTheEnds(v, 12, pts, 1e-4f);
    }
    // widths are tiny, so a ring is within a few thousandths of its centre
    {
      Cartoon c(0.001f, 0.001f);
      for (size_t i = 0; i < pts.size(); ++i)
        c.addPoint(pts[i], idColor(i), 0, i, i % 2 ? SS::alphaHelix : SS::coil);
      c.tessellate(0, v, idx);
      expectReachesTheEnds(v, 20, pts, 0.01f);
    }
    {
      Cartoon c; // a plain tube of the cartoon's cross-section
      for (size_t i = 0; i < pts.size(); ++i)
        c.CurveGeometry::addPoint(pts[i], idColor(i), 0.001f, 0, i);
      c.tessellate(0, v, idx);
      expectReachesTheEnds(v, 20, pts, 0.01f);
    }
    {
      Cartoon ribbon(-0.001f, -0.001f); // flat ribbon, two vertices a ring
      for (size_t i = 0; i < pts.size(); ++i)
        ribbon.CurveGeometry::addPoint(pts[i], idColor(i), -0.001f, 0, i);
      ribbon.tessellate(0, v, idx);
      expectReachesTheEnds(v, 2, pts, 0.01f);
    }
    {
      BSplineGeometry trace; // a line
      for (size_t i = 0; i < pts.size(); ++i)
        trace.addPoint(pts[i], idColor(i), -0.15f, 0, i);
      trace.tessellate(0, v, idx);
      expectReachesTheEnds(v, 1, pts, 1e-4f);
      EXPECT_EQ(colorId(v.front().color), 0u);
      EXPECT_EQ(colorId(v.back().color), pts.size() - 1);
    }
  }
}

TEST(BSplineGeometryTest, endRingsHaveASensibleFrame)
{
  const auto pts = helix(20);
  BSplineGeometry g(false);
  fill(g, pts, 0.1f);
  std::vector<ColorNormalVertex> v;
  std::vector<unsigned int> idx;
  g.tessellate(0, v, idx);
  for (size_t ring : { size_t(0), v.size() / 12 - 1 }) {
    // finite, radius 0.1
    Vector3f c = Vector3f::Zero();
    for (size_t j = 0; j < 12; ++j)
      c += v[ring * 12 + j].vertex / 12.0f;
    for (size_t j = 0; j < 12; ++j) {
      const auto& x = v[ring * 12 + j];
      ASSERT_TRUE(x.vertex.allFinite());
      EXPECT_NEAR((x.vertex - c).norm(), 0.1f, 1e-4f);
      // normals carry the scale; the shader normalises them
      EXPECT_NEAR(x.normal.norm(), 0.1f, 1e-4f);
    }
  }
  // the first ring's axis points from P0 towards P1 (the ring is
  // perpendicular to it)
  Vector3f axis = (pts[1] - pts[0]).normalized();
  for (size_t j = 0; j < 12; ++j)
    EXPECT_NEAR((v[j].vertex - pts[0]).dot(axis), 0.0f, 1e-3f);
}

TEST(BSplineGeometryTest, shortChains)
{
  for (int n = 0; n <= 3; ++n) {
    const auto pts = wobble(n);
    BSplineGeometry g(false);
    fill(g, pts, 0.1f);
    Cartoon c(0.2f, 1.5f);
    for (size_t i = 0; i < pts.size(); ++i)
      c.addPoint(pts[i], idColor(i), 0, i, SS::alphaHelix);
    for (CurveGeometry* geometry :
         std::initializer_list<CurveGeometry*>{ &g, &c }) {
      std::vector<ColorNormalVertex> v;
      std::vector<unsigned int> idx;
      if (n == 0)
        continue; // no line at all
      geometry->tessellate(0, v, idx);
      if (n == 1) {
        EXPECT_TRUE(v.empty());
        EXPECT_TRUE(idx.empty());
        continue;
      }
      EXPECT_FALSE(v.empty()) << n;
      EXPECT_FALSE(idx.empty()) << n;
      EXPECT_TRUE(allFinite(v));
      for (unsigned int i : idx)
        ASSERT_LT(i, v.size());
    }
  }
  // two residues: a short tube between the two C-alphas
  const auto pts = wobble(2);
  BSplineGeometry g(false);
  fill(g, pts, 0.1f);
  const Rings r = rings(g);
  ASSERT_GT(r.centre.size(), 10u);
  checkChain(pts, r);
  const Vector3f axis = (pts[1] - pts[0]).normalized();
  for (const auto& c : r.centre) {
    // within the capsule of the chord, and the sweep never goes backwards
    EXPECT_LT((c - pts[0] - axis * (c - pts[0]).dot(axis)).norm(), 1e-3f);
  }
}

TEST(BSplineGeometryTest, cartoonWidthsStayPositiveAtTheEnds)
{
  const SS kinds[] = { SS::alphaHelix, SS::betaSheet, SS::coil };
  for (SS kind : kinds) {
    for (int n : { 2, 3, 4, 6, 12 }) {
      for (int mix = 0; mix < 2; ++mix) {
        const auto pts = wobble(n);
        Cartoon c(0.2f, 1.5f);
        for (int i = 0; i < n; ++i)
          c.addPoint(pts[i], idColor(i), 0, i,
                     mix && i == n / 2 ? SS::coil : kind);
        std::vector<ColorNormalVertex> v;
        std::vector<unsigned int> idx;
        c.tessellate(0, v, idx);
        ASSERT_FALSE(v.empty());
        for (size_t ring = 0; ring * 20 < v.size(); ++ring) {
          Vector3f lo = v[ring * 20].vertex, hi = lo;
          for (size_t j = 0; j < 20; ++j) {
            const auto& x = v[ring * 20 + j];
            ASSERT_TRUE(x.vertex.allFinite() && x.normal.allFinite());
            lo = lo.cwiseMin(x.vertex);
            hi = hi.cwiseMax(x.vertex);
          }
          // the cross-section has a size, between the thinnest and the
          // widest cartoon
          EXPECT_GT((hi - lo).norm(), 0.05f);
          EXPECT_LT((hi - lo).norm(), 4.0f);
        }
      }
    }
  }
}

namespace {

// Largest distance between two vertices of one 20-sided ring, and the
// direction of that chord.
struct RingShape
{
  float diameter = 0.0f;
  Vector3f major = Vector3f::UnitX();
};

std::vector<RingShape> ringShapes(const std::vector<ColorNormalVertex>& v)
{
  std::vector<RingShape> shapes;
  for (size_t base = 0; base + 20 <= v.size(); base += 20) {
    RingShape s;
    for (size_t j = 0; j < 20; ++j) {
      for (size_t k = j + 1; k < 20; ++k) {
        const Vector3f d = v[base + j].vertex - v[base + k].vertex;
        if (d.norm() > s.diameter) {
          s.diameter = d.norm();
          s.major = d.normalized();
        }
      }
    }
    shapes.push_back(s);
  }
  return shapes;
}

// ring diameter of a Cartoon(0.2, 1.5) tube of a given scale
constexpr float kBody = 0.3f;     // 1.5 x the 0.2 minimum radius
constexpr float kStrand = 0.975f; // 1.5 x (0.3 x 1.5 + 0.2)

// widths of the rings owned by residue `owner` (colour = residue index)
std::vector<float> widthsOwnedBy(const std::vector<ColorNormalVertex>& v,
                                 size_t owner)
{
  std::vector<float> widths;
  const auto shapes = ringShapes(v);
  for (size_t r = 0; r < shapes.size(); ++r)
    if (colorId(v[r * 20].color) == owner)
      widths.push_back(shapes[r].diameter);
  return widths;
}

std::vector<ColorNormalVertex> cartoonWithTypes(const std::vector<SS>& types)
{
  const auto pts = wobble(static_cast<int>(types.size()));
  Cartoon c(0.2f, 1.5f);
  for (size_t i = 0; i < pts.size(); ++i)
    c.addPoint(pts[i], idColor(i), 0, i, types[i]);
  std::vector<ColorNormalVertex> v;
  std::vector<unsigned int> idx;
  c.tessellate(0, v, idx);
  return v;
}

} // namespace

TEST(BSplineGeometryTest, terminalSheetResiduesAreNotBlocks)
{
  // 1CRN ends in a lone sheet residue (46) after coil, and starts with a
  // strand; a head squeezed into the half residue at a terminus used to flare
  // to five times the coil width
  const size_t n = 20;
  for (int mirror = 0; mirror < 2; ++mirror) {
    // a lone sheet residue at the end, then at the start
    std::vector<SS> types(n, SS::coil);
    types[mirror ? 0 : n - 1] = SS::betaSheet;
    const auto v = cartoonWithTypes(types);
    for (size_t owner = 0; owner < n; ++owner)
      for (float w : widthsOwnedBy(v, owner))
        EXPECT_NEAR(w, kBody, 2e-3f) << "lone sheet at " << (mirror ? "N" : "C")
                                     << "-terminus, residue " << owner;
  }
  for (int mirror = 0; mirror < 2; ++mirror) {
    // a strand running to the terminus: flat strand width, no flare, at the
    // terminal residues
    std::vector<SS> types(n, SS::coil);
    for (size_t i = 0; i < 4; ++i)
      types[mirror ? i : n - 1 - i] = SS::betaSheet;
    const auto v = cartoonWithTypes(types);
    const size_t end = mirror ? 0 : n - 1;
    const size_t inner = mirror ? 1 : n - 2;
    for (size_t owner : { end, inner })
      for (float w : widthsOwnedBy(v, owner))
        EXPECT_LE(w, kStrand + 2e-3f) << (mirror ? "N" : "C") << " " << owner;
    for (float w : widthsOwnedBy(v, end))
      EXPECT_NEAR(w, kStrand, 2e-3f);
  }
}

TEST(BSplineGeometryTest, ellipseOrientationDoesNotJumpAtTheEnds)
{
  const size_t n = 24;
  std::vector<SS> types(n, SS::coil);
  for (size_t i : { size_t(0), size_t(1), n - 2, n - 1 })
    types[i] = SS::betaSheet;
  const auto v = cartoonWithTypes(types);
  const auto shapes = ringShapes(v);
  ASSERT_GT(shapes.size(), 100u);
  float worst = 1.0f;
  for (size_t r = 1; r < shapes.size(); ++r)
    worst = std::min(worst, std::abs(shapes[r].major.dot(shapes[r - 1].major)));
  // consecutive rings never turn their broad side by more than 35 degrees
  EXPECT_GT(worst, std::cos(35.0f * Avogadro::DEG_TO_RAD_F));
}
