/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "beziergeometry.h"

namespace Avogadro {
namespace Rendering {

BezierGeometry::BezierGeometry() : CurveGeometry() {}

Vector3f BezierGeometry::computeCurvePoint(float t,
                                           const std::list<Point*>& points)
{
  Vector3f h;
  h << 1.0f, 1.0f, 1.0f;
  float u = 1.0f - t;
  float n1 = points.size();
  float w = 1.0f / n1;
  float k = 0.0f;
  Vector3f Q;
  Q << w, w, w;
  for (const auto& p : points) {
    for (size_t i = 0; i < 3; ++i) {
      h[i] = h[i] * t * (n1 - k) * w;
      h[i] = h[i] / (k * u * w + h[i]);
      Q[i] = (1.0f - h[i]) * Q[i] + h[i] * p->pos[i];
    }
    k += 1.0f;
  }
  return Q;
}

} // namespace Rendering
} // namespace Avogadro
