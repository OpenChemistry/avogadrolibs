/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

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

namespace {

// Reference copy of the original recursive Cox-de Boor evaluation.
float refB(float i, float k, float t, float knot)
{
  float ti = knot * i;
  float ti1 = knot * (i + 1.0f);
  if (k == 1) {
    if (ti <= t && t < ti1)
      return 1.0f;
    return 0.0f;
  }
  float tik = knot * (i + k);
  float tik1 = knot * (i + k - 1.0f);
  float a1 = (t - ti) / (tik1 - ti);
  float a2 = refB(i, k - 1, t, knot);
  float b1 = (tik - t) / (tik - ti1);
  float b2 = refB(i + 1, k - 1, t, knot);
  return a1 * a2 + b1 * b2;
}

Vector3f refCurvePoint(float t, const std::vector<Vector3f>& points)
{
  float k = 3.0f;
  const int lookahead = 10;
  float m = 2 * lookahead + k + 1.0f;
  float knot = 1.0f / m;
  Vector3f Q = Vector3f::Zero();
  int size = static_cast<int>(points.size());
  int maxStart = std::max(0, size - 2 * lookahead);
  int startIndex =
    std::clamp(static_cast<int>(size * t) - lookahead, 0, maxStart);
  float t2 = (t - startIndex / (float)size) * size / (2 * lookahead);
  const int endIndex = std::min(size, startIndex + 2 * lookahead);
  float i = 0.0f;
  for (int pointIndex = startIndex; pointIndex < endIndex; ++pointIndex) {
    Q += points[pointIndex] * refB(i, k, t2, knot);
    i += 1.0f;
  }
  return Q;
}

class TestSpline : public BSplineGeometry
{
public:
  Vector3f eval(float t) const
  {
    return computeCurvePoint(t, lines()[0]->points);
  }
};

} // namespace

TEST(BSplineGeometryTest, matchesRecursiveReference)
{
  std::mt19937 rng(12345);
  std::uniform_real_distribution<float> coord(-20.0f, 20.0f);
  float maxDiff = 0.0f;
  size_t samples = 0;
  for (int n = 1; n <= 60; ++n) {
    TestSpline spline;
    std::vector<Vector3f> pts;
    for (int i = 0; i < n; ++i) {
      Vector3f p(coord(rng), coord(rng), coord(rng));
      pts.push_back(p);
      spline.addPoint(p, Vector3ub(1, 2, 3), 0.1f, 0, static_cast<size_t>(i));
    }
    // Includes slightly out-of-range values on both ends.
    const int steps = 40 * n + 40;
    for (int s = -5; s <= steps; ++s) {
      float t = static_cast<float>(s) / static_cast<float>(steps - 5) * 1.0f;
      Vector3f a = spline.eval(t);
      Vector3f b = refCurvePoint(t, pts);
      float d = (a - b).cwiseAbs().maxCoeff();
      maxDiff = std::max(maxDiff, d);
      ++samples;
    }
  }
  std::printf("BSpline max abs difference: %g over %zu samples\n", maxDiff,
              samples);
  EXPECT_LT(maxDiff, 1e-4f);
}
