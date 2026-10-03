/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "tessellatingvisitor.h"

#include "arrowgeometry.h"
#include "cartoongeometry.h"
#include "curvegeometry.h"
#include "cylindergeometry.h"
#include "dashedlinegeometry.h"
#include "linestripgeometry.h"
#include "meshgeometry.h"
#include "spheregeometry.h"
#include "widelinegeometry.h"

#include <avogadro/core/avogadrocore.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <unordered_map>

namespace Avogadro::Rendering {

namespace {

constexpr float kMinLength = 1e-6f;
constexpr unsigned int kLineSides = 8;
constexpr unsigned int kArrowSides = 12; // same as ArrowGeometry on screen

bool isFinite(const Vector3f& v)
{
  return std::isfinite(v[0]) && std::isfinite(v[1]) && std::isfinite(v[2]);
}

unsigned char alphaFromOpacity(float opacity)
{
  if (!std::isfinite(opacity))
    return 255;
  return static_cast<unsigned char>(
    std::lround(std::clamp(opacity, 0.0f, 1.0f) * 255.0f));
}

Vector4ub withAlpha(const Vector3ub& c, unsigned char alpha)
{
  return Vector4ub(c[0], c[1], c[2], alpha);
}

Vector4ub lerpColor(const Vector4ub& a, const Vector4ub& b, float t)
{
  Vector4ub result;
  for (int i = 0; i < 4; ++i) {
    float value = (1.0f - t) * a[i] + t * b[i];
    result[i] =
      static_cast<unsigned char>(std::lround(std::clamp(value, 0.0f, 255.0f)));
  }
  return result;
}

// Unit vectors (cos, sin) of the sides of a circle.
std::vector<std::pair<float, float>> circleTable(unsigned int sides)
{
  std::vector<std::pair<float, float>> table;
  table.reserve(sides);
  for (unsigned int j = 0; j < sides; ++j) {
    float theta = 2.0f * PI_F * static_cast<float>(j) / sides;
    table.emplace_back(std::cos(theta), std::sin(theta));
  }
  return table;
}

void addVertex(TessellatedMesh& mesh, const Vector3f& position,
               const Vector3f& normal, const Vector4ub& color)
{
  mesh.positions.push_back(position);
  mesh.normals.push_back(normal);
  mesh.colors.push_back(color);
}

void addTriangle(TessellatedMesh& mesh, unsigned int a, unsigned int b,
                 unsigned int c)
{
  mesh.indices.push_back(a);
  mesh.indices.push_back(b);
  mesh.indices.push_back(c);
}

unsigned int vertexCount(const TessellatedMesh& mesh)
{
  return static_cast<unsigned int>(mesh.positions.size());
}

// A tube with a circular cross-section along a polyline. The colour is
// interpolated along the tube (as it is on screen for two-colour cylinders).
// Rings are placed at each point, perpendicular to the averaged tangent, and
// the ring frame is parallel-transported to avoid twisting. Consecutive
// coincident points are dropped; fewer than two distinct points, or a
// non-positive radius, produce nothing. Winding is counter-clockwise seen from
// outside.
void appendTube(TessellatedMesh& mesh, const std::vector<Vector3f>& points,
                const std::vector<Vector4ub>& colors, float radius,
                unsigned int sides, bool capStart, bool capEnd)
{
  if (points.size() != colors.size() || !(radius > 0.0f) ||
      !std::isfinite(radius) || sides < 3)
    return;

  std::vector<Vector3f> pts;
  std::vector<Vector4ub> cols;
  pts.reserve(points.size());
  cols.reserve(points.size());
  for (size_t i = 0; i < points.size(); ++i) {
    if (!isFinite(points[i]))
      continue;
    if (!pts.empty() && (points[i] - pts.back()).norm() < kMinLength)
      continue;
    pts.push_back(points[i]);
    cols.push_back(colors[i]);
  }
  const size_t n = pts.size();
  if (n < 2)
    return;

  std::vector<Vector3f> segments(n - 1);
  for (size_t i = 0; i + 1 < n; ++i)
    segments[i] = (pts[i + 1] - pts[i]).normalized();

  const auto table = circleTable(sides);
  const unsigned int base = vertexCount(mesh);
  mesh.positions.reserve(mesh.positions.size() + n * sides);
  mesh.normals.reserve(mesh.normals.size() + n * sides);
  mesh.colors.reserve(mesh.colors.size() + n * sides);

  Vector3f u = Vector3f::Zero();
  Vector3f firstTangent = segments.front();
  Vector3f lastTangent = segments.back();
  for (size_t i = 0; i < n; ++i) {
    Vector3f tangent;
    if (i == 0) {
      tangent = segments.front();
    } else if (i == n - 1) {
      tangent = segments.back();
    } else {
      tangent = segments[i - 1] + segments[i];
      tangent = tangent.norm() < 1e-4f ? segments[i] : tangent.normalized();
    }

    if (i == 0) {
      u = tangent.unitOrthogonal();
    } else {
      u -= tangent * u.dot(tangent);
      u = u.norm() < 1e-4f ? Vector3f(tangent.unitOrthogonal())
                           : Vector3f(u.normalized());
    }
    const Vector3f v = tangent.cross(u);

    for (const auto& cs : table) {
      Vector3f radial = u * cs.first + v * cs.second;
      addVertex(mesh, pts[i] + radius * radial, radial, cols[i]);
    }
  }

  for (size_t i = 0; i + 1 < n; ++i) {
    const unsigned int ring0 = base + static_cast<unsigned int>(i) * sides;
    const unsigned int ring1 = ring0 + sides;
    for (unsigned int j = 0; j < sides; ++j) {
      unsigned int j1 = (j + 1) % sides;
      addTriangle(mesh, ring0 + j, ring0 + j1, ring1 + j);
      addTriangle(mesh, ring0 + j1, ring1 + j1, ring1 + j);
    }
  }

  // End caps: a centre vertex and a duplicated ring with the axis as normal.
  auto addCap = [&](size_t pointIndex, const Vector3f& normal, bool outward) {
    const unsigned int ringStart =
      base + static_cast<unsigned int>(pointIndex) * sides;
    const unsigned int center = vertexCount(mesh);
    addVertex(mesh, pts[pointIndex], normal, cols[pointIndex]);
    const unsigned int capRing = vertexCount(mesh);
    for (unsigned int j = 0; j < sides; ++j)
      addVertex(mesh, mesh.positions[ringStart + j], normal, cols[pointIndex]);
    for (unsigned int j = 0; j < sides; ++j) {
      unsigned int j1 = (j + 1) % sides;
      if (outward)
        addTriangle(mesh, center, capRing + j, capRing + j1);
      else
        addTriangle(mesh, center, capRing + j1, capRing + j);
    }
  };
  if (capStart)
    addCap(0, -firstTangent, false);
  if (capEnd)
    addCap(n - 1, lastTangent, true);
}

void appendTube(TessellatedMesh& mesh, const Vector3f& p1, const Vector3f& p2,
                const Vector4ub& c1, const Vector4ub& c2, float radius,
                unsigned int sides, bool capStart = true, bool capEnd = true)
{
  appendTube(mesh, { p1, p2 }, { c1, c2 }, radius, sides, capStart, capEnd);
}

// A cone with its base disc closed. Side normals are the true slant normals;
// the tip is duplicated per side so that each side has its own normal.
void appendCone(TessellatedMesh& mesh, const Vector3f& base,
                const Vector3f& tip, float radius, const Vector4ub& color,
                unsigned int sides)
{
  Vector3f axis = tip - base;
  const float length = axis.norm();
  if (!isFinite(axis) || length < kMinLength || !(radius > 0.0f) ||
      !std::isfinite(radius) || sides < 3)
    return;
  axis /= length;
  const Vector3f u = axis.unitOrthogonal();
  const Vector3f v = axis.cross(u);
  const auto table = circleTable(sides);

  const unsigned int ringStart = vertexCount(mesh);
  for (const auto& cs : table) {
    Vector3f radial = u * cs.first + v * cs.second;
    Vector3f normal = (radial * length + axis * radius).normalized();
    addVertex(mesh, base + radius * radial, normal, color);
  }
  const unsigned int tipStart = vertexCount(mesh);
  for (const auto& cs : table) {
    Vector3f radial = u * cs.first + v * cs.second;
    Vector3f normal = (radial * length + axis * radius).normalized();
    addVertex(mesh, tip, normal, color);
  }
  for (unsigned int j = 0; j < sides; ++j) {
    unsigned int j1 = (j + 1) % sides;
    addTriangle(mesh, ringStart + j, ringStart + j1, tipStart + j);
  }

  // Base disc, facing back along the axis.
  const unsigned int center = vertexCount(mesh);
  addVertex(mesh, base, -axis, color);
  const unsigned int discStart = vertexCount(mesh);
  for (const auto& cs : table) {
    Vector3f radial = u * cs.first + v * cs.second;
    addVertex(mesh, base + radius * radial, -axis, color);
  }
  for (unsigned int j = 0; j < sides; ++j) {
    unsigned int j1 = (j + 1) % sides;
    addTriangle(mesh, center, discStart + j1, discStart + j);
  }
}

void keepIfNotEmpty(std::vector<TessellatedMesh>& meshes,
                    TessellatedMesh&& mesh)
{
  if (!mesh.positions.empty() && !mesh.indices.empty())
    meshes.push_back(std::move(mesh));
}

} // namespace

TessellatingVisitor::TessellatingVisitor() = default;

TessellatingVisitor::~TessellatingVisitor() = default;

void TessellatingVisitor::begin()
{
  clear();
}

void TessellatingVisitor::clear()
{
  m_meshes.clear();
}

bool TessellatingVisitor::bounds(Vector3f& minimum, Vector3f& maximum) const
{
  bool any = false;
  Vector3f lo = Vector3f::Zero(), hi = Vector3f::Zero();
  for (const auto& mesh : m_meshes) {
    for (const auto& p : mesh.positions) {
      if (!any) {
        lo = hi = p;
        any = true;
      } else {
        lo = lo.cwiseMin(p);
        hi = hi.cwiseMax(p);
      }
    }
  }
  if (any) {
    minimum = lo;
    maximum = hi;
  }
  return any;
}

void TessellatingVisitor::setTessellationTolerance(float angstrom)
{
  if (std::isfinite(angstrom) && angstrom > 0.0f)
    m_tolerance = angstrom;
}

void TessellatingVisitor::setSphereLevelRange(unsigned int minLevel,
                                              unsigned int maxLevel)
{
  m_minLevel = std::min(minLevel, 6u);
  m_maxLevel = std::max(std::min(maxLevel, 6u), m_minLevel);
}

void TessellatingVisitor::setSphereSubdivisions(unsigned int level)
{
  m_fixedSphereLevel = static_cast<int>(std::min(level, 6u));
}

unsigned int TessellatingVisitor::sphereSubdivisions() const
{
  return m_fixedSphereLevel >= 0 ? static_cast<unsigned int>(m_fixedSphereLevel)
                                 : m_minLevel;
}

void TessellatingVisitor::setCylinderSides(unsigned int sides)
{
  m_fixedCylinderSides = std::max(sides, 3u);
}

unsigned int TessellatingVisitor::cylinderSidesForRadius(float radius) const
{
  if (m_fixedCylinderSides != 0)
    return m_fixedCylinderSides;
  constexpr unsigned int minSides = 8, maxSides = 48;
  if (!(radius > m_tolerance) || !std::isfinite(radius))
    return minSides;
  const float angle = std::acos(1.0f - m_tolerance / radius);
  if (!(angle > 0.0f))
    return maxSides;
  const float sides = std::ceil(PI_F / angle);
  return std::clamp(sides >= static_cast<float>(maxSides)
                      ? maxSides
                      : static_cast<unsigned int>(sides),
                    minSides, maxSides);
}

unsigned int TessellatingVisitor::sphereLevelForRadius(float radius)
{
  if (m_fixedSphereLevel >= 0)
    return static_cast<unsigned int>(m_fixedSphereLevel);
  for (unsigned int level = m_minLevel; level < m_maxLevel; ++level) {
    const float sagitta =
      radius * (1.0f - std::cos(sphereMaxEdgeAngle(level) / 2.0f));
    if (sagitta <= m_tolerance)
      return level;
  }
  return m_maxLevel;
}

float TessellatingVisitor::sphereMaxEdgeAngle(unsigned int level)
{
  return icosphere(std::min(level, 6u)).maxEdgeAngle;
}

void TessellatingVisitor::setLineRadius(float radius)
{
  if (std::isfinite(radius) && radius > 0.0f)
    m_lineRadius = radius;
}

const TessellatingVisitor::Icosphere& TessellatingVisitor::icosphere(
  unsigned int level)
{
  if (m_icospheres.size() < 7)
    m_icospheres.resize(7);
  Icosphere& result = m_icospheres[level];
  if (result.built)
    return result;

  const float t = (1.0f + std::sqrt(5.0f)) / 2.0f;
  std::vector<Vector3f> vertices = { Vector3f(-1, t, 0),  Vector3f(1, t, 0),
                                     Vector3f(-1, -t, 0), Vector3f(1, -t, 0),
                                     Vector3f(0, -1, t),  Vector3f(0, 1, t),
                                     Vector3f(0, -1, -t), Vector3f(0, 1, -t),
                                     Vector3f(t, 0, -1),  Vector3f(t, 0, 1),
                                     Vector3f(-t, 0, -1), Vector3f(-t, 0, 1) };
  for (auto& vertex : vertices)
    vertex.normalize();

  // Counter-clockwise seen from outside.
  std::vector<unsigned int> indices = {
    0, 11, 5,  0, 5,  1, 0, 1, 7, 0, 7,  10, 0, 10, 11, 1, 5, 9, 5, 11,
    4, 11, 10, 2, 10, 7, 6, 7, 1, 8, 3,  9,  4, 3,  4,  2, 3, 2, 6, 3,
    6, 8,  3,  8, 9,  4, 9, 5, 2, 4, 11, 6,  2, 10, 8,  6, 7, 9, 8, 1
  };

  for (unsigned int step = 0; step < level; ++step) {
    // Shared midpoints: one new vertex per edge, not per face.
    std::unordered_map<std::uint64_t, unsigned int> midpoints;
    auto midpoint = [&](unsigned int a, unsigned int b) {
      const std::uint64_t key =
        (static_cast<std::uint64_t>(std::min(a, b)) << 32) | std::max(a, b);
      auto found = midpoints.find(key);
      if (found != midpoints.end())
        return found->second;
      Vector3f mid = (vertices[a] + vertices[b]).normalized();
      auto index = static_cast<unsigned int>(vertices.size());
      vertices.push_back(mid);
      midpoints.emplace(key, index);
      return index;
    };

    std::vector<unsigned int> refined;
    refined.reserve(indices.size() * 4);
    for (size_t i = 0; i + 2 < indices.size(); i += 3) {
      const unsigned int a = indices[i];
      const unsigned int b = indices[i + 1];
      const unsigned int c = indices[i + 2];
      const unsigned int ab = midpoint(a, b);
      const unsigned int bc = midpoint(b, c);
      const unsigned int ca = midpoint(c, a);
      const unsigned int tris[12] = { a, ab, ca, b,  bc, ab,
                                      c, ca, bc, ab, bc, ca };
      refined.insert(refined.end(), tris, tris + 12);
    }
    indices.swap(refined);
  }

  // Edges are not uniform after subdivision: measure the real maximum.
  float minDot = 1.0f;
  for (size_t i = 0; i + 2 < indices.size(); i += 3) {
    for (size_t k = 0; k < 3; ++k) {
      const Vector3f& p = vertices[indices[i + k]];
      const Vector3f& q = vertices[indices[i + (k + 1) % 3]];
      minDot = std::min(minDot, p.dot(q));
    }
  }
  result.maxEdgeAngle = std::acos(std::clamp(minDot, -1.0f, 1.0f));
  result.vertices = std::move(vertices);
  result.indices = std::move(indices);
  result.built = true;
  return result;
}

void TessellatingVisitor::visit(SphereGeometry& geometry)
{
  const auto& spheres = geometry.spheres();
  if (spheres.size() == 0)
    return;

  const unsigned char alpha = alphaFromOpacity(geometry.opacity());
  TessellatedMesh mesh;
  mesh.name = "spheres";

  for (const auto& sphere : spheres) {
    if (!isFinite(sphere.center) || !(sphere.radius > 0.0f) ||
        !std::isfinite(sphere.radius))
      continue;
    const Icosphere& ico = icosphere(sphereLevelForRadius(sphere.radius));
    const Vector4ub color = withAlpha(sphere.color, alpha);
    const unsigned int base = vertexCount(mesh);
    for (const auto& direction : ico.vertices)
      addVertex(mesh, sphere.center + sphere.radius * direction, direction,
                color);
    for (unsigned int index : ico.indices)
      mesh.indices.push_back(base + index);
  }
  keepIfNotEmpty(m_meshes, std::move(mesh));
}

void TessellatingVisitor::visit(CylinderGeometry& geometry)
{
  const unsigned char alpha = alphaFromOpacity(geometry.opacity());
  TessellatedMesh mesh;
  mesh.name = "cylinders";
  // On screen the end1 ring has `color`, the end2 ring `color2`, and the GPU
  // interpolates between them: the same is done here by vertex colour.
  for (const auto& cylinder : geometry.cylinders())
    appendTube(mesh, cylinder.end1, cylinder.end2,
               withAlpha(cylinder.color, alpha),
               withAlpha(cylinder.color2, alpha), cylinder.radius,
               cylinderSidesForRadius(cylinder.radius));
  keepIfNotEmpty(m_meshes, std::move(mesh));
}

void TessellatingVisitor::visit(MeshGeometry& geometry)
{
  // Meshes are indexed and may share vertices: keep the index data as is.
  const MeshGeometry& mesh = geometry;
  const auto& vertices = mesh.vertices();
  const auto& triangles = mesh.triangles();

  TessellatedMesh result;
  result.name = "mesh";
  result.positions.reserve(vertices.size());
  result.normals.reserve(vertices.size());
  result.colors.reserve(vertices.size());
  // The alpha channel of each vertex colour already includes the mesh
  // opacity() (it is applied when the vertices are added), and the mesh
  // shader uses it unchanged.
  for (size_t i = 0; i < vertices.size(); ++i)
    addVertex(result, vertices[i].vertex, vertices[i].normal,
              vertices[i].color);

  result.indices.reserve(triangles.size());
  for (size_t i = 0; i + 2 < triangles.size(); i += 3) {
    if (triangles[i] >= vertices.size() ||
        triangles[i + 1] >= vertices.size() ||
        triangles[i + 2] >= vertices.size())
      continue;
    addTriangle(result, triangles[i], triangles[i + 1], triangles[i + 2]);
  }
  keepIfNotEmpty(m_meshes, std::move(result));
}

void TessellatingVisitor::visit(CurveGeometry& geometry)
{
  TessellatedMesh mesh;
  mesh.name = dynamic_cast<Cartoon*>(&geometry) ? "cartoon" : "curves";

  std::vector<ColorNormalVertex> vertices;
  std::vector<unsigned int> indices;
  const auto& lines = geometry.lines();
  for (size_t i = 0; i < lines.size(); ++i) {
    geometry.tessellate(i, vertices, indices);
    if (vertices.empty())
      continue;

    if (geometry.isFlatLine(i)) {
      // Drawn on screen as a GL line strip of -radius pixels: export a thin
      // tube along the centre line.
      std::vector<Vector3f> points;
      std::vector<Vector4ub> colors;
      for (const auto& vertex : vertices) {
        points.push_back(vertex.vertex);
        colors.push_back(withAlpha(vertex.color, 255));
      }
      const float width = std::max(1.0f, -lines[i]->radius);
      appendTube(mesh, points, colors, m_lineRadius * width, kLineSides, true,
                 true);
      continue;
    }

    // The curve normals carry the local tube scale (the shaders normalize
    // them); consumers expect unit normals.
    const unsigned int base = vertexCount(mesh);
    for (const auto& vertex : vertices) {
      const float norm = vertex.normal.norm();
      const Vector3f normal = norm > 1e-8f && std::isfinite(norm)
                                ? Vector3f(vertex.normal / norm)
                                : Vector3f::UnitY();
      addVertex(mesh, vertex.vertex, normal, withAlpha(vertex.color, 255));
    }
    for (unsigned int index : indices)
      mesh.indices.push_back(base + index);
  }
  keepIfNotEmpty(m_meshes, std::move(mesh));
}

void TessellatingVisitor::visit(LineStripGeometry& geometry)
{
  const auto vertices = geometry.vertices();
  const auto& starts = geometry.lineStarts();
  const auto& widths = geometry.lineWidths();
  if (starts.size() != widths.size())
    return;

  TessellatedMesh mesh;
  mesh.name = "lines";
  for (size_t s = 0; s < starts.size(); ++s) {
    const size_t first = starts[s];
    const size_t last = s + 1 < starts.size() ? starts[s + 1] : vertices.size();
    if (first >= last || last > vertices.size())
      continue;
    std::vector<Vector3f> points;
    std::vector<Vector4ub> colors;
    for (size_t i = first; i < last; ++i) {
      points.push_back(vertices[i].vertex);
      colors.push_back(vertices[i].color);
    }
    const float width = std::max(1.0f, widths[s]);
    appendTube(mesh, points, colors, m_lineRadius * width, kLineSides, true,
               true);
  }
  keepIfNotEmpty(m_meshes, std::move(mesh));
}

void TessellatingVisitor::visit(WideLineGeometry& geometry)
{
  // Four vertices per segment: this endpoint, the other end, colour, and
  // +-half-width in scene units (the shader offsets by it in view space, so
  // it is a true world-space width). Solid lines are extended by the half
  // width at both ends (square caps). Dashed lines carry lineParam =
  // 0..2*dashCount, drawn where mod(lineParam, 2) <= 1.
  const auto& vertices = geometry.vertices();
  TessellatedMesh mesh;
  mesh.name = "lines";
  for (size_t k = 0; k + 3 < vertices.size(); k += 4) {
    const auto& v0 = vertices[k];
    const auto& v2 = vertices[k + 2];
    const Vector3f start = v0.position;
    const Vector3f end = v0.otherEnd;
    if (!isFinite(start) || !isFinite(end))
      continue;
    const float halfWidth = std::fabs(v0.widthSide);
    const float radius = halfWidth > 0.0f ? halfWidth : m_lineRadius;
    const Vector3f delta = end - start;
    const float length = delta.norm();
    if (length < kMinLength)
      continue;
    const Vector3f direction = delta / length;

    if (v2.lineParam > 0.0f) {
      const long dashCount = std::lround(v2.lineParam / 2.0f);
      for (long d = 0; d < dashCount; ++d) {
        float t0 = static_cast<float>(d) / dashCount;
        float t1 = (static_cast<float>(d) + 0.5f) / dashCount;
        appendTube(mesh, start + delta * t0, start + delta * t1,
                   lerpColor(v0.color, v2.color, t0),
                   lerpColor(v0.color, v2.color, t1), radius, kLineSides);
      }
    } else {
      appendTube(mesh, start - direction * halfWidth,
                 end + direction * halfWidth, v0.color, v2.color, radius,
                 kLineSides);
    }
  }
  keepIfNotEmpty(m_meshes, std::move(mesh));
}

void TessellatingVisitor::visit(DashedLineGeometry& geometry)
{
  // Vertices are GL_LINES pairs: (v[2k], v[2k+1]) is one dash. The GL line
  // width is in pixels, so scale the tube radius by it (see lineRadius()).
  const auto& vertices = geometry.vertices();
  const float width = std::max(1.0f, static_cast<float>(geometry.lineWidth()));
  TessellatedMesh mesh;
  mesh.name = "dashedlines";
  for (size_t i = 0; i + 1 < vertices.size(); i += 2)
    appendTube(mesh, vertices[i].vertex, vertices[i + 1].vertex,
               vertices[i].color, vertices[i + 1].color, m_lineRadius * width,
               kLineSides);
  keepIfNotEmpty(m_meshes, std::move(mesh));
}

void TessellatingVisitor::visit(ArrowGeometry& geometry)
{
  // Proportions as on screen (arrowgeometry.cpp): 80% cylindrical shaft and
  // 20% cone head; shaft radius 0.02 * length, cone radius 0.05 * length,
  // both times radiusScale(). Arrows have no opacity.
  TessellatedMesh mesh;
  mesh.name = "arrows";
  const float scale = geometry.radiusScale();
  for (const auto& arrow : geometry.arrows()) {
    const Vector3f delta = arrow.end - arrow.start;
    const float length = delta.norm();
    if (!isFinite(delta) || length < kMinLength)
      continue;
    const Vector3f axis = delta / length;
    const Vector4ub color = withAlpha(arrow.color, 255);
    const Vector3f shaftEnd = arrow.start + axis * (0.8f * length);
    appendTube(mesh, arrow.start, shaftEnd, color, color,
               0.02f * length * scale, kArrowSides, true, false);
    appendCone(mesh, shaftEnd, arrow.end, 0.05f * length * scale, color,
               kArrowSides);
  }
  keepIfNotEmpty(m_meshes, std::move(mesh));
}

} // namespace Avogadro::Rendering
