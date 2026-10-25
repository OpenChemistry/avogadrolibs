/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_TESTS_RENDERING_LEGACYSPLINE_H
#define AVOGADRO_TESTS_RENDERING_LEGACYSPLINE_H

#include <avogadro/core/vector.h>

#include <algorithm>
#include <cmath>
#include <vector>

namespace LegacySpline {

// Reference copy of the recursive Cox-de Boor evaluation that BSplineGeometry
// used before the spline became a global uniform B-spline: an order 3 spline
// with knot = 1 / 24 over a sliding 20-point window, so the curve moved 1.2
// knot intervals per control point and jumped each time the window slid.
inline float basis(float i, float k, float t, float knot)
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
  float a2 = basis(i, k - 1, t, knot);
  float b1 = (tik - t) / (tik - ti1);
  float b2 = basis(i + 1, k - 1, t, knot);
  return a1 * a2 + b1 * b2;
}

inline Avogadro::Vector3f curvePoint(
  float t, const std::vector<Avogadro::Vector3f>& points)
{
  float k = 3.0f;
  const int lookahead = 10;
  float m = 2 * lookahead + k + 1.0f;
  float knot = 1.0f / m;
  Avogadro::Vector3f Q = Avogadro::Vector3f::Zero();
  int size = static_cast<int>(points.size());
  int maxStart = std::max(0, size - 2 * lookahead);
  int startIndex =
    std::clamp(static_cast<int>(size * t) - lookahead, 0, maxStart);
  float t2 = (t - startIndex / (float)size) * size / (2 * lookahead);
  const int endIndex = std::min(size, startIndex + 2 * lookahead);
  float i = 0.0f;
  for (int pointIndex = startIndex; pointIndex < endIndex; ++pointIndex) {
    Q += points[pointIndex] * basis(i, k, t2, knot);
    i += 1.0f;
  }
  return Q;
}

// The samples the old tessellate() drew: 15 per control point from control
// point SKIPPED (1) to n - margin, minus the first, which only seeded the
// tangent. `colorIndex` is the control point whose colour the old code used
// for the strip ending at each sample (it started at 3).
struct Sample
{
  Avogadro::Vector3f pos;
  size_t colorIndex;
};

inline std::vector<Sample> samples(const std::vector<Avogadro::Vector3f>& pts)
{
  std::vector<Sample> result;
  const size_t n = pts.size();
  const size_t res = 15;
  const size_t margin = std::min<size_t>(4, (n + 5) / 6);
  const size_t top = n <= margin + 2 ? 0 : n - margin;
  size_t colorIndex = n > 3 ? 3u : 0u;
  for (size_t i = 1; i < top; ++i) {
    for (size_t j = 0; j < res; ++j) {
      const float t = (i * res + j) / float(res * n);
      if (i > 1) {
        if (result.size() % res == 0 && !result.empty() && colorIndex + 1 < n)
          ++colorIndex;
        result.push_back({ curvePoint(t, pts), colorIndex });
      }
    }
  }
  return result;
}

} // namespace LegacySpline

#endif
