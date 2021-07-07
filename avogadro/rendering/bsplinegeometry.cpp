/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "bsplinegeometry.h"

namespace Avogadro {
namespace Rendering {

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

Vector3f BSplineGeometry::computeCurvePoint(float t,
                                            const std::list<Point*>& points)
{
  // degree: line = 1, cuadratic = 2, cube = 3
  float k = 3.0f;
  // #knot segments = #control points + #degree + 1
  float m = points.size() + k + 1.0f;
  float knot = 1.0f / m;
  Vector3f Q;
  Q << 0.0f, 0.0f, 0.0f;
  float i = 0.0f;
  for (const auto& p : points) {
    Q += p->pos * B(i, k, t, knot);
    i += 1.0f;
  }
  return Q;
}

} // namespace Rendering
} // namespace Avogadro
