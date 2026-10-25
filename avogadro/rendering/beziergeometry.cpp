/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "beziergeometry.h"

namespace Avogadro::Rendering {

BezierGeometry::BezierGeometry() : CurveGeometry() {}

Vector3f BezierGeometry::computeSegmentPoint(
  size_t segment, float f, const std::vector<Point>& points) const
{
  if (points.size() < 2)
    return points.empty() ? Vector3f::Zero() : points.front().pos;
  const float last = static_cast<float>(points.size() - 1);
  return computeCurvePoint(residueCoordinate(segment, f, points.size()) / last,
                           points);
}

Vector3f BezierGeometry::computeCurvePoint(
  float t, const std::vector<Point>& points) const
{
  if (points.empty())
    return Vector3f::Zero();
  // the end points; the iteration below divides 0 by 0 at t = 0
  if (!(t > 0.0f))
    return points.front().pos;
  if (t >= 1.0f)
    return points.back().pos;
  Vector3f h = Vector3f::Ones();
  float u = 1.0f - t;
  float n1 = points.size();
  float w = 1.0f / n1;
  float k = 0.0f;
  Vector3f Q(w, w, w);
  for (const auto& p : points) {
    for (size_t i = 0; i < 3; ++i) {
      h[i] = h[i] * t * (n1 - k) * w;
      h[i] = h[i] / (k * u * w + h[i]);
      Q[i] = (1.0f - h[i]) * Q[i] + h[i] * p.pos[i];
    }
    k += 1.0f;
  }
  return Q;
}

} // namespace Avogadro::Rendering
