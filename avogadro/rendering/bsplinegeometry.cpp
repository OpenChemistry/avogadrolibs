/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "bsplinegeometry.h"

namespace Avogadro {
namespace Rendering {

BSplineGeometry::BSplineGeometry() : CurveGeometry() {}

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

void BSplineGeometry::update(int index)
{
  // compute the intermidian bezier points
  Line* line = m_lines[index];
  unsigned int lineResolution = line->flat ? 30 : 12;
  size_t qttyPoints = line->points.size();
  std::vector<Vector3f> points;
  size_t qttySegments = lineResolution * qttyPoints;
  for (size_t i = 0; i < qttyPoints; ++i) {
    for (size_t j = 0; j < lineResolution; ++j) {
      auto p = computeCurvePoint((i * lineResolution + j) / float(qttySegments),
                                 line->points);
      // workarround p is exactly (0,0,0)
      if (p.norm() > 0.0f) {
        points.push_back(p);
      }
    }
  }

  // prepare VBO and EBO
  std::vector<unsigned int> indices;
  std::vector<ColorNormalVertex> vertices;
  unsigned int circleResolution = line->flat ? 1 : 12;
  const float resolutionRadians =
    2.0f * static_cast<float>(M_PI) / static_cast<float>(circleResolution);
  std::vector<Vector3f> radials(circleResolution);

  auto it = line->points.begin();
  float radius = line->radius;
  qttySegments = points.size();
  for (size_t i = lineResolution * 2; i < (qttySegments - (lineResolution * 2));
       ++i) {
    if (i % lineResolution == 0) {
      ++it;
    }
    const Point* point = *it;
    const Vector3f& position1 = points[i - 1];
    const Vector3f& position2 = points[i];
    const Vector3f direction = (position2 - position1).normalized();

    Vector3f radial = direction.unitOrthogonal() * radius;
    Eigen::AngleAxisf transform(resolutionRadians, direction);
    for (unsigned int j = 0; j < circleResolution; ++j) {
      radials[j] = radial;
      radial = transform * radial;
    }

    ColorNormalVertex vert1(point->color, -direction, position1);
    ColorNormalVertex vert2(point->color, -direction, position1);
    for (const auto& normal : radials) {
      vert1.normal = normal;
      vert1.vertex = position1 + normal;
      vertices.push_back(vert1);

      vert2.normal = normal;
      vert2.vertex = position2 + normal;
      vertices.push_back(vert2);
    }

    // Now to stitch it together. we select the indices
    const unsigned int tubeStart = static_cast<unsigned int>(vertices.size());
    for (unsigned int j = 0; j < circleResolution; ++j) {
      unsigned int r1 = j + j;
      unsigned int r2 = (j != 0 ? r1 : circleResolution + circleResolution) - 2;
      indices.push_back(tubeStart + r1);
      indices.push_back(tubeStart + r1 + 1);
      indices.push_back(tubeStart + r2);

      indices.push_back(tubeStart + r2);
      indices.push_back(tubeStart + r1 + 1);
      indices.push_back(tubeStart + r2 + 1);
    }
  }

  line->vbo.upload(vertices, BufferObject::ArrayBuffer);
  line->ibo.upload(indices, BufferObject::ElementArrayBuffer);
  line->numberOfVertices = vertices.size();
  line->numberOfIndices = indices.size();

  line->dirty = false;
}

std::multimap<float, Identifier> BSplineGeometry::hits(const Vector3f&,
                                                       const Vector3f&,
                                                       const Vector3f&) const
{
  return std::multimap<float, Identifier>();
}

} // namespace Rendering
} // namespace Avogadro
