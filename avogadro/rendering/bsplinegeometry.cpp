/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "bsplinegeometry.h"

#include <algorithm>

namespace Avogadro::Rendering {

BSplineGeometry::BSplineGeometry() : CurveGeometry() {}
BSplineGeometry::BSplineGeometry(bool flat) : CurveGeometry(flat) {}

Vector3f BSplineGeometry::computeSegmentPoint(
  size_t segment, float f, const std::vector<Point>& points) const
{
  // Uniform quadratic B-spline (C1) with the end control points doubled,
  // P' = P0 P0 P1 ... Pn-1 Pn-1, so that it starts at P0 and ends at Pn-1.
  // Segment k blends P'k, P'k+1 and P'k+2, which are the control points
  // k - 1, k and k + 1 clamped to the chain. f = 0 and f = 1 are the
  // midpoints of the chords before and after control point k (the end points
  // themselves for the first and last segment), and f = 0.5 is closest to k.
  const size_t size = points.size();
  if (size == 0)
    return Vector3f::Zero();
  const size_t last = size - 1;
  const float weights[3] = { (1.0f - f) * (1.0f - f) * 0.5f,
                             (-2.0f * f * f + 2.0f * f + 1.0f) * 0.5f,
                             f * f * 0.5f };
  const size_t index[3] = { segment > 0 ? std::min(segment - 1, last) : 0,
                            std::min(segment, last),
                            std::min(segment + 1, last) };
  Vector3f q = Vector3f::Zero();
  for (size_t n = 0; n < 3; ++n)
    q += points[index[n]].pos * weights[n];
  return q;
}

} // namespace Avogadro::Rendering
