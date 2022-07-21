/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "bsplinegeometry.h"

namespace Avogadro::Rendering {

BSplineGeometry::BSplineGeometry() : CurveGeometry() {}
BSplineGeometry::BSplineGeometry(bool flat) : CurveGeometry(flat) {}

float B(float i, float k, float t, float knot)
{
  float ti = knot * i;           // t_i
  float ti1 = knot * (i + 1.0f); // t_(i+1)
  if (k == 1) {
    if (ti <= t && t < ti1) {
      return 1.0f;
    } else {
      return 0.0f;
    }
  }

  float tik = knot * (i + k);         // t_(i+k)
  float tik1 = knot * (i + k - 1.0f); // t_(i+k-1)

  float a1 = (t - ti) / (tik1 - ti);
  float a2 = B(i, k - 1, t, knot);

  float b1 = (tik - t) / (tik - ti1);
  float b2 = B(i + 1, k - 1, t, knot);
  return a1 * a2 + b1 * b2;
}

Vector3f BSplineGeometry::computeCurvePoint(
  float t, const std::list<Point*>& points) const
{
  // degree: linear = 1, quadratic = 2, cubic = 3
  float k = 3.0f;
  // how many points in either way for approximation
  const int lookahead = 10;
  // #knot segments = #control points + #degree + 1
  float m = 2 * lookahead + k + 1.0f;
  float knot = 1.0f / m;
  Vector3f Q = Vector3f::Zero();
  float i = 0.0f;
  auto it = points.begin();
  const auto end = points.end();
  size_t size = points.size();
  // start from a lookbehind distance rather than at the beginning
  int startIndex = (size * t) - lookahead;
  if (startIndex < 0) startIndex = 0;
  else if (startIndex > size - 2 * lookahead) startIndex = size - 2 * lookahead;
  float t2 = (t - startIndex / (float) size) * size / (2 * lookahead);
  for (; startIndex > 0 && it != end; --startIndex, ++it) {}
  // only read a certain number of elements from here
  size_t count = 2 * lookahead;
  for (; count && it != end; --count, ++it) {
    Q += (*it)->pos * B(i, k, t2, knot);
    i += 1.0f;
  }
  return Q;
}

} // namespace Avogadro
