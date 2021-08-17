/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "geometryvisitor.h"

#include "ambientocclusionspheregeometry.h"
#include "curvegeometry.h"
#include "linestripgeometry.h"
#include "spheregeometry.h"

namespace Avogadro {
namespace Rendering {

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
  const Core::Array<SphereColor>& spheres = geometry.spheres();
  if (!spheres.size())
    return;

  m_dirty = true;

  Vector3f tmpCenter(Vector3f::Zero());
  // First find the center of the sphere geometry.
  std::vector<SphereColor>::const_iterator it = spheres.begin();
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

void GeometryVisitor::visit(AmbientOcclusionSphereGeometry& geometry)
{
  const Core::Array<SphereColor>& spheres = geometry.spheres();
  if (!spheres.size())
    return;

  m_dirty = true;

  Vector3f tmpCenter(Vector3f::Zero());
  // First find the center of the sphere geometry.
  std::vector<SphereColor>::const_iterator it = spheres.begin();
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

void GeometryVisitor::visit(LineStripGeometry& lsg)
{
  typedef Core::Array<LineStripGeometry::PackedVertex> VertexArray;
  const VertexArray verts(lsg.vertices());
  if (!verts.size())
    return;

  m_dirty = true;

  Vector3f tmpCenter(Vector3f::Zero());
  for (VertexArray::const_iterator it = verts.begin(), itEnd = verts.end();
       it != itEnd; ++it) {
    tmpCenter += it->vertex;
  }
  tmpCenter /= static_cast<float>(verts.size());

  float tmpRadius(0.f);
  for (VertexArray::const_iterator it = verts.begin(), itEnd = verts.end();
       it != itEnd; ++it) {
    float distance = (it->vertex - tmpCenter).squaredNorm();
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

} // End namespace Rendering
} // End namespace Avogadro
