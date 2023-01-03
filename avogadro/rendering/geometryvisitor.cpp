/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "geometryvisitor.h"

#include "ambientocclusionspheregeometry.h"
#include "curvegeometry.h"
#include "linestripgeometry.h"
#include "spheregeometry.h"
#ifdef TDX_INTEGRATION
#include "cylindergeometry.h"
#endif

namespace Avogadro::Rendering {

GeometryVisitor::GeometryVisitor()
  : m_center(Vector3f::Zero()), m_radius(0.0f), m_dirty(false)
{
}

GeometryVisitor::~GeometryVisitor()
{
}

void GeometryVisitor::visit(Drawable&)
{
}

void GeometryVisitor::visit(SphereGeometry& geometry)
{
#ifdef TDX_INTEGRATION
  m_sphereGeometries.push_back(geometry);
#endif
  const Core::Array<SphereColor>& spheres = geometry.spheres();
  if (!spheres.size())
    return;

  m_dirty = true;

  Vector3f tmpCenter(Vector3f::Zero());
  // First find the center of the sphere geometry.
  auto it = spheres.begin();
  for (; it != spheres.end(); ++it)
    tmpCenter += it->center;
  tmpCenter /= static_cast<float>(spheres.size());

  // Now find its radius.
  float tmpRadius(0.0f);
  if (spheres.size() > 1) {
    for (it = spheres.begin(); it != spheres.end(); ++it) {
      float distance = (it->center - tmpCenter).squaredNorm();
      if (distance > tmpRadius)
        tmpRadius = distance;
#ifdef TDX_INTEGRATION
	  m_spheres.push_back(*it);
#endif
    }
  }
  tmpRadius = std::sqrt(tmpRadius);
  m_centers.push_back(tmpCenter);
  m_radii.push_back(tmpRadius);
}

void GeometryVisitor::visit(AmbientOcclusionSphereGeometry& geometry)
{
  const Core::Array<SphereColor>& spheres = geometry.spheres();
  if (!spheres.size())
    return;

  m_dirty = true;

  Vector3f tmpCenter(Vector3f::Zero());
  // First find the center of the sphere geometry.
  auto it = spheres.begin();
  for (; it != spheres.end(); ++it)
    tmpCenter += it->center;
  tmpCenter /= static_cast<float>(spheres.size());

  // Now find its radius.
  float tmpRadius(0.0f);
  if (spheres.size() > 1) {
    for (it = spheres.begin(); it != spheres.end(); ++it) {
      float distance = (it->center - tmpCenter).squaredNorm();
      if (distance > tmpRadius)
        tmpRadius = distance;
    }
  }
  tmpRadius = std::sqrt(tmpRadius);
  m_centers.push_back(tmpCenter);
  m_radii.push_back(tmpRadius);
}

void GeometryVisitor::visit(CurveGeometry& cg)
{
  const auto& lines = cg.lines();
  if (lines.size() == 0) {
    return;
  }
  m_dirty = true;
  float qtty = 0.0f;
  Vector3f tmpCenter(Vector3f::Zero());
  for (const auto& line : lines) {
    for (const auto& point : line->points) {
      tmpCenter += point->pos;
    }
    qtty += line->points.size();
  }
  tmpCenter /= qtty;

  float tmpRadius = 0.0f;
  for (const auto& line : lines) {
    for (const auto& point : line->points) {
      float distance = (point->pos - tmpCenter).squaredNorm();
      if (distance > tmpRadius)
        tmpRadius = distance;
    }
  }
  m_centers.push_back(tmpCenter);
  m_radii.push_back(std::sqrt(tmpRadius));
}
#ifdef TDX_INTEGRATION
void GeometryVisitor::visit(CylinderGeometry& geometry) {
  m_cylinderGeometries.push_back(geometry);
}
#endif
void GeometryVisitor::visit(LineStripGeometry& lsg)
{
  typedef Core::Array<LineStripGeometry::PackedVertex> VertexArray;
  const VertexArray verts(lsg.vertices());
  if (!verts.size())
    return;

  m_dirty = true;

  Vector3f tmpCenter(Vector3f::Zero());
  for (const auto & vert : verts) {
    tmpCenter += vert.vertex;
  }
  tmpCenter /= static_cast<float>(verts.size());

  float tmpRadius(0.f);
  for (const auto & vert : verts) {
    float distance = (vert.vertex - tmpCenter).squaredNorm();
    if (distance > tmpRadius)
      tmpRadius = distance;
  }

  m_centers.push_back(tmpCenter);
  m_radii.push_back(std::sqrt(tmpRadius));
}

void GeometryVisitor::clear()
{
  m_center = Vector3f::Zero();
  m_radius = 0.0f;
  m_dirty = false;
  m_centers.clear();
  m_radii.clear();
#ifdef TDX_INTEGRATION
  m_spheres.clear();
  m_sphereGeometries.clear();
  m_cylinderGeometries.clear();
#endif
}

Vector3f GeometryVisitor::center()
{
  average();
  return m_center;
}

float GeometryVisitor::radius()
{
  average();
  return m_radius;
}
#ifdef TDX_INTEGRATION
void GeometryVisitor::boundingBox(double& minX,
								  double& minY,
								  double& minZ,
                                  double& maxX,
								  double& maxY,
								  double& maxZ,
                                  const std::vector<bool> &flags) const
{ 
  minX = std::numeric_limits<double>::max();
  minY = minX;
  minZ = minX;
  maxX = -minX;
  maxY = maxX;
  maxZ = maxX;

  bool noSelection = true;

  for (uint32_t i = 0; i < flags.size(); i++) {
    if (flags[i]) {
      noSelection = false;
      break;
    }
  }
    
  for (uint32_t i = 0; i < m_spheres.size(); i++) {

    if (flags.empty() || noSelection || flags[i]) {

      float radius = m_spheres[i].radius + 0.5f;

      double bufferMinX = m_spheres[i].center.x() - radius;
      double bufferMinY = m_spheres[i].center.y() - radius;
      double bufferMinZ = m_spheres[i].center.z() - radius;
      double bufferMaxX = m_spheres[i].center.x() + radius;
      double bufferMaxY = m_spheres[i].center.y() + radius;
      double bufferMaxZ = m_spheres[i].center.z() + radius;

      if (bufferMinX < minX)
        minX = bufferMinX;

      if (bufferMinY < minY)
        minY = bufferMinY;

      if (bufferMinZ < minZ)
        minZ = bufferMinZ;

      if (bufferMaxX > maxX)
        maxX = bufferMaxX;

      if (bufferMaxY > maxY)
        maxY = bufferMaxY;

      if (bufferMaxZ > maxZ)
        maxZ = bufferMaxZ;
    }
  }
}

float GeometryVisitor::hit(const Vector3f &rayOrigin,
						   const Vector3f &rayDirection, 
						   const float rayLength)
{
  auto minDistance = [rayOrigin, rayDirection, rayLength]
                     (const std::vector<const Drawable*> &drawables) -> float {
    float result = std::numeric_limits<float>::max();

    for (auto &drawable : drawables) {
      std::multimap<float, Avogadro::Rendering::Identifier> hitsMap =
        drawable->hits(rayOrigin,
					   rayOrigin + rayLength * rayDirection,
                       rayDirection);

      for (auto& hit : hitsMap) {
        if (hit.first < result)
          result = hit.first;
      } 
    }
    return result;
  };

  std::vector<const Drawable*> pDrawables;
  pDrawables.reserve(m_sphereGeometries.size() + m_cylinderGeometries.size());

  for (auto& m_sphereGeometry : m_sphereGeometries)
    pDrawables.push_back(&m_sphereGeometry);

  for (auto& m_cylinderGeometry : m_cylinderGeometries)
    pDrawables.push_back(&m_cylinderGeometry);

  float result = minDistance(pDrawables);

  return result < std::numeric_limits<float>::max() ? result : -1.0f;
}
#endif
void GeometryVisitor::average()
{
  if (!m_dirty)
    return;

  // Find the average position of the center, then the minimal enclosing radius.
  m_dirty = false;
  if (m_centers.size() == 1) {
    m_center = m_centers[0];
    m_radius = m_radii[0];
  } else {
    m_center = Vector3f::Zero();
    std::vector<Vector3f>::const_iterator cit;
    for (cit = m_centers.begin(); cit != m_centers.end(); ++cit)
      m_center += *cit;
    m_center /= static_cast<float>(m_centers.size());
    // Now find the smallest enclosing radius for the new center.
    m_radius = 0.0f;
    std::vector<float>::const_iterator rit;
    for (cit = m_centers.begin(), rit = m_radii.begin();
         cit != m_centers.end() && rit != m_radii.end(); ++cit, ++rit) {
      float distance = (m_center - (*cit)).norm() + (*rit);
      if (distance > m_radius)
        m_radius = distance;
    }
  }
}

} // End namespace Avogadro
