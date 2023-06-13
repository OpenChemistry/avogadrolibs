/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "camera.h"
#include "cylindergeometry.h"
#include "geometryvisitor.h"
#include "scene.h"
#include "spheregeometry.h"

void Avogadro::Rendering::Camera::calculatePerspective(float left, float right,
                                                       float bottom, float top,
                                                       float zNear, float zFar)
{
  m_data->projection.setIdentity();

  m_data->projection(0, 0) = (2.0f * zNear) / (right - left);
  m_data->projection(1, 1) = (2.0f * zNear) / (top - bottom);
  m_data->projection(0, 2) = (right + left) / (right - left);
  m_data->projection(1, 2) = (top + bottom) / (top - bottom);
  m_data->projection(2, 2) = -(zFar + zNear) / (zFar - zNear);
  m_data->projection(3, 2) = -1.0f;
  m_data->projection(2, 3) = -(2.0f * zFar * zNear) / (zFar - zNear);
  m_data->projection(3, 3) = 0.0f;
}

void Avogadro::Rendering::Scene::getBoundingBox(double& minX, double& minY,
                                                double& minZ, double& maxX,
                                                double& maxY, double& maxZ,
                                                const std::vector<bool>& flags)
{
  GeometryVisitor visitor;

  m_rootNode.accept(visitor);
  visitor.boundingBox(minX, minY, minZ, maxX, maxY, maxZ, flags);
}

float Avogadro::Rendering::Scene::getHitDistance(const Vector3f& rayOrigin,
                                                 const Vector3f& rayDirection,
                                                 const float rayLength)
{
  GeometryVisitor visitor;

  m_rootNode.accept(visitor);
  return visitor.hit(rayOrigin, rayDirection, rayLength);
}

void Avogadro::Rendering::GeometryVisitor::visit(CylinderGeometry& geometry)
{
  m_cylinderGeometries.push_back(geometry);
}

void Avogadro::Rendering::GeometryVisitor::boundingBox(
  double& minX, double& minY, double& minZ, double& maxX, double& maxY,
  double& maxZ, const std::vector<bool>& flags) const
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

float Avogadro::Rendering::GeometryVisitor::hit(const Vector3f& rayOrigin,
                                                const Vector3f& rayDirection,
                                                const float rayLength)
{
  auto minDistance = [rayOrigin, rayDirection, rayLength](
                       const std::vector<const Drawable*>& drawables) -> float {
    float result = std::numeric_limits<float>::max();

    for (auto& drawable : drawables) {
      std::multimap<float, Avogadro::Rendering::Identifier> hitsMap =
        drawable->hits(rayOrigin, rayOrigin + rayLength * rayDirection,
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
