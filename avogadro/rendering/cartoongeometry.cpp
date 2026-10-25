/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cartoongeometry.h"

#include <algorithm>
#include <cmath>

namespace Avogadro::Rendering {

using Core::Residue;
using std::vector;

const float Cartoon::ELIPSE_RATIO = 0.75f;

// A run of equal secondary structure counts up its residues only once more than
// this many are in; the first three each restart at 0.
constexpr size_t kMinSizeToExtendRun = 2;

Cartoon::Cartoon()
  : BSplineGeometry(false), m_minRadius(-1.0f), m_maxRadius(-1.0f)
{
}

Cartoon::Cartoon(float minRadius, float maxRadius)
  : BSplineGeometry(false), m_minRadius(minRadius), m_maxRadius(maxRadius)
{
}

size_t Cartoon::circleResolution(bool flat) const
{
  return flat ? 2u : sidesOr(kDefaultSides);
}

void Cartoon::fillRingTemplate(std::vector<Vector3f>& ring, bool flat) const
{
  ring.clear();
  const size_t resolution = circleResolution(flat);
  const float resolutionRadians =
    2.0f * static_cast<float>(M_PI) / static_cast<float>(resolution);
  float elipseA = flat ? 0.999f : ELIPSE_RATIO;
  float elipseB = 1.0f - elipseA;
  float e = std::sqrt(1.0f - ((elipseB * elipseB) / (elipseA * elipseA)));
  float c = elipseA * e;
  for (size_t i = 0; i < resolution; ++i) {
    float theta = resolutionRadians * i;
    float r = (elipseA * (1.0f - (e * e))) / (1.0f + e * std::cos(theta));
    ring.emplace_back(r * std::sin(theta), 0.0f, c + r * std::cos(theta));
  }
}

float arrowFunction(float t)
{
  float result;
  const float maxPoint = 0.7f;
  if (t < maxPoint) {
    // normalize t using max point and scale it so that adding will be between
    // [minimumRadius, 1]
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
  if (index >= m_type.size())
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
        // The first and last control points own only half a residue of curve,
        // too short for the flare of an arrow head: it would be a wide block.
        // A head that ends the chain continues the strand's width, and a lone
        // sheet residue there is as thin as coil.
        if (index == 0 || index + 1 == m_type.size()) {
          const bool strand = index > 0 && m_type[index - 1].first == Arrow;
          return strand ? 0.3f * m_maxRadius + m_minRadius : m_minRadius;
        }
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
    case Residue::SecondaryStructure::helix310:
      return Tail;
    case Residue::SecondaryStructure::piHelix:
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
    idCartoon = ct == m_type.back().first && m_type.size() > kMinSizeToExtendRun
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
  m_type.emplace_back(ct, idCartoon);
  BSplineGeometry::addPoint(pos, color, m_minRadius, group, id);
}

} // namespace Avogadro::Rendering
