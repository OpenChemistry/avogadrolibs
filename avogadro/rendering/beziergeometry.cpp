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
  const size_t size = points.size();
  if (size == 0)
    return Vector3f::Zero();
  if (size == 1)
    return points.front().pos;
  const size_t last = size - 1;
  if (segment >= size)
    return points.back().pos;
  // index of the control point the curve is centred on
  float centre;
  if (segment == 0)
    centre = 0.5f * f;
  else if (segment == last)
    centre = static_cast<float>(last) - 0.5f + 0.5f * f;
  else
    centre = static_cast<float>(segment) - 0.5f + f;
  return computeCurvePoint(centre / static_cast<float>(last), points);
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
