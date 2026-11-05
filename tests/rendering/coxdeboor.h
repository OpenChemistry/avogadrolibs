/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_TESTS_RENDERING_COXDEBOOR_H
#define AVOGADRO_TESTS_RENDERING_COXDEBOOR_H

namespace CurveTest {

// B-spline basis function i of order k at t, for uniform knots at knot * i:
// the recursive Cox-de Boor definition, as an independent reference for the
// closed-form spline of BSplineGeometry.
inline float coxDeBoor(float i, float k, float t, float knot)
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
  float a2 = coxDeBoor(i, k - 1, t, knot);
  float b1 = (tik - t) / (tik - ti1);
  float b2 = coxDeBoor(i + 1, k - 1, t, knot);
  return a1 * a2 + b1 * b2;
}

} // namespace CurveTest

#endif
