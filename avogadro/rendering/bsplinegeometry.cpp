/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "bsplinegeometry.h"

#include <algorithm>

namespace Avogadro::Rendering {

BSplineGeometry::BSplineGeometry() : CurveGeometry() {}
BSplineGeometry::BSplineGeometry(bool flat) : CurveGeometry(flat) {}

Vector3f BSplineGeometry::computeCurvePoint(
  float t, const std::vector<Point>& points) const
{
  // order (degree + 1): linear = 2, quadratic = 3, cubic = 4
  // (this is a quadratic B-spline)
  float k = 3.0f;
  // how many points in either way for approximation
  const int lookahead = 10;
  // #knot segments = #control points + #degree + 1
  float m = 2 * lookahead + k + 1.0f;
  float knot = 1.0f / m;
  Vector3f Q = Vector3f::Zero();
  int size = static_cast<int>(points.size());
  // start from a lookbehind distance rather than at the beginning
  int maxStart = std::max(0, size - 2 * lookahead);
  int startIndex =
    std::clamp(static_cast<int>(size * t) - lookahead, 0, maxStart);
  float t2 = (t - startIndex / (float)size) * size / (2 * lookahead);
  const int endIndex = std::min(size, startIndex + 2 * lookahead);
  const int count = endIndex - startIndex;
  // Uniform knots at i * knot: for u = t2 / knot in [s, s + 1) only the basis
  // functions s - 2, s - 1 and s (quadratic, order 3) are non-zero. Basis
  // functions outside the [0, count) window of control points are dropped.
  const float u = t2 / knot;
  if (!(u >= 0.0f) || u >= static_cast<float>(count + 2))
    return Q;
  const int s = static_cast<int>(u);
  const float f = u - static_cast<float>(s);
  const float weights[3] = { (1.0f - f) * (1.0f - f) * 0.5f,
                             (-2.0f * f * f + 2.0f * f + 1.0f) * 0.5f,
                             f * f * 0.5f };
  for (int n = 0; n < 3; ++n) {
    const int i = s - 2 + n;
    if (i >= 0 && i < count)
      Q += points[startIndex + i].pos * weights[n];
  }
  return Q;
}

} // namespace Avogadro::Rendering
