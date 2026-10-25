/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "bsplinegeometry.h"

#include <algorithm>
#include <cmath>

namespace Avogadro::Rendering {

BSplineGeometry::BSplineGeometry() : CurveGeometry() {}
BSplineGeometry::BSplineGeometry(bool flat) : CurveGeometry(flat) {}

Vector3f BSplineGeometry::computeSegmentPoint(
  size_t segment, float f, const std::vector<Point>& points) const
{
  // Uniform quadratic B-spline (C1): segment k blends control points k,
  // k + 1 and k + 2. f = 0 and f = 1 are the midpoints of the chords
  // P_k P_{k+1} and P_{k+1} P_{k+2}; f = 0.5 is closest to P_{k+1}.
  const size_t size = points.size();
  if (size == 0)
    return Vector3f::Zero();
  const size_t last = size - 1;
  const float weights[3] = { (1.0f - f) * (1.0f - f) * 0.5f,
                             (-2.0f * f * f + 2.0f * f + 1.0f) * 0.5f,
                             f * f * 0.5f };
  Vector3f q = Vector3f::Zero();
  for (size_t n = 0; n < 3; ++n)
    q += points[std::min(segment + n, last)].pos * weights[n];
  return q;
}

Vector3f BSplineGeometry::computeCurvePoint(
  float t, const std::vector<Point>& points) const
{
  const size_t size = points.size();
  if (size < 3)
    return size == 0 ? Vector3f::Zero() : points.front().pos;
  if (!(t >= 0.0f))
    t = 0.0f; // also catches NaN
  const size_t segments = size - 2;
  const float s = std::min(t, 1.0f) * static_cast<float>(segments);
  const size_t segment = std::min(static_cast<size_t>(s), segments - 1);
  return computeSegmentPoint(segment, s - static_cast<float>(segment), points);
}

} // namespace Avogadro::Rendering
