/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cartoongeometry.h"

#include <cmath>
#include <iostream>

namespace Avogadro {
namespace Rendering {

const float Cartoon::ELIPSE_RATIO = 0.65f;

Cartoon::Cartoon() : BSplineGeometry(false) {}

std::vector<ColorNormalVertex> Cartoon::computeCirclePoints(
  const Eigen::Affine3f& a, const Eigen::Affine3f& b, float radius, bool flat)
{
  unsigned int circleResolution = flat ? 2 : 12;
  const float resolutionRadians =
    2.0f * static_cast<float>(M_PI) / static_cast<float>(circleResolution);
  std::vector<ColorNormalVertex> result;
  float elipseA = flat ? 0.999f : ELIPSE_RATIO;
  float elipseB = 1.0f - elipseA;
  float e = std::sqrt(1.0f - ((elipseB * elipseB) / (elipseA * elipseA)));
  float c = elipseA * e;
  for (unsigned int i = 0; i < circleResolution; ++i) {
    float theta = resolutionRadians * i;
    float r = (elipseA * (1.0f - (e * e))) / (1.0f + e * std::cos(theta));
    Vector3f elipse =
      Vector3f(c + r * std::cos(theta), 0.0f, r * std::sin(theta)) * radius;

    ColorNormalVertex vert1;
    vert1.normal = a.linear() * elipse;
    vert1.vertex = a * elipse;
    vert1.color = Vector3ub(0.7f, 0.7f, 0.7f);
    result.push_back(vert1);

    ColorNormalVertex vert2;
    vert2.normal = b.linear() * elipse;
    vert2.vertex = b * elipse;
    vert2.color = Vector3ub(0.7f, 0.7f, 0.7f);
    result.push_back(vert2);
  }
  return result;
}

} // namespace Rendering
} // namespace Avogadro
