/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cartoongeometry.h"

#include <cmath>

namespace Avogadro {
namespace Rendering {

using Core::Residue;
using std::make_pair;
using std::vector;

const float Cartoon::ELIPSE_RATIO = 0.75f;

Cartoon::Cartoon()
  : BSplineGeometry(false), m_minRadius(-1.0f), m_maxRadius(-1.0f)
{}

Cartoon::Cartoon(float minRadius, float maxRadius)
  : BSplineGeometry(false), m_minRadius(minRadius), m_maxRadius(maxRadius)
{}

vector<ColorNormalVertex> Cartoon::computeCirclePoints(const Eigen::Affine3f& a,
                                                       const Eigen::Affine3f& b,
                                                       bool flat) const
{
  unsigned int circleResolution = flat ? 2 : 20;
  const float resolutionRadians =
    2.0f * static_cast<float>(M_PI) / static_cast<float>(circleResolution);
  vector<ColorNormalVertex> result;
  float elipseA = flat ? 0.999f : ELIPSE_RATIO;
  float elipseB = 1.0f - elipseA;
  float e = std::sqrt(1.0f - ((elipseB * elipseB) / (elipseA * elipseA)));
  float c = elipseA * e;
  for (unsigned int i = 0; i < circleResolution; ++i) {
    float theta = resolutionRadians * i;
    float r = (elipseA * (1.0f - (e * e))) / (1.0f + e * std::cos(theta));
    Vector3f elipse =
      Vector3f(r * std::sin(theta), 0.0f, c + r * std::cos(theta));

    ColorNormalVertex vert1;
    vert1.normal = a.linear() * elipse;
    vert1.vertex = a * elipse;
    result.push_back(vert1);

    ColorNormalVertex vert2;
    vert2.normal = b.linear() * elipse;
    vert2.vertex = b * elipse;
    result.push_back(vert2);
  }
  return result;
}

float arrowFunction(float t)
{
  float result;
  const float maxPoint = 0.7f;
  if (t < maxPoint) {
    // normalize t using max point and scale it so that adding will be between
    // [minimunRadius, 1]
    result = t / maxPoint;
  } else {
    // starting with 1 and go decreassing
    t = (t - maxPoint) / (1.0f - maxPoint);
    result = 1.0f - t;
    result = result < 0.3 ? 0.3 : result;
  }
  return result;
}

float Cartoon::computeScale(size_t index, float p, float radius) const
{
  if (index > m_type.size())
    return radius;
  float t = (m_type[index].second + p) / 0.80f;
  t = t > 1.0f ? 1.0f : t;
  switch (m_type[index].first) {
    default:
    case Undefined:
      return radius;
    case Body:
      return m_minRadius;
    case Arrow:
      if (m_type[index].second == 0) {
        return (arrowFunction(1.0f - t) * m_maxRadius) + m_minRadius;
      } else {
        return 0.3 * m_maxRadius + m_minRadius;
      }
    case Head:
      return ((1.0f - t) * (m_maxRadius - m_minRadius)) + (1.0f * m_minRadius);
    case Tail:
      return (t * (m_maxRadius - m_minRadius)) + (1.0f * m_minRadius);
  }
}

CartoonType secondaryToCartoonType(Residue::SecondaryStructure sec)
{
  switch (sec) {
    case Residue::SecondaryStructure::betaSheet:
      return Arrow;
    case Residue::SecondaryStructure::alphaHelix:
      return Tail;
    default:
      return Body;
  }
}

void Cartoon::addPoint(const Vector3f& pos, const Vector3ub& color,
                       size_t group, size_t id, Residue::SecondaryStructure sec)
{
  CartoonType ct = secondaryToCartoonType(sec);
  size_t idCartoon = 0;
  if (m_type.size() > 0) {
    idCartoon = ct == m_type.back().first && m_type.size() > (SKIPPED + 1)
                  ? m_type.back().second + 1
                  : 0;
    if (Tail == m_type.back().first && ct == Body) {
      for (size_t i = m_type.size(), j = 0;
           i > 0 && j < std::ceil(m_type.back().second / 2.0f); --i, ++j) {
        m_type[i - 1].first = Head;
        m_type[i - 1].second = j;
      }
    }
    if (ct == Arrow && m_type.back().first == Arrow) {
      m_type.back().second = 1;
      idCartoon = 0;
    }
  }
  m_type.push_back(make_pair(ct, idCartoon));
  BSplineGeometry::addPoint(pos, color, m_minRadius, group, id);
}

} // namespace Rendering
} // namespace Avogadro
