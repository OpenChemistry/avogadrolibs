/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "scene.h"

#include <Eigen/Geometry>

#include <iostream>

namespace Avogadro {
namespace Rendering {

Scene::Scene()
  : m_dirty(false), m_centerDirty(false),
    m_center(Vector3f::Zero()), m_radius(0.0)
{
}

Scene::~Scene()
{
}

Vector3f Scene::center() const
{
  if (!m_centerDirty)
    return m_center;

  if (m_spheres.size() > 0)
    m_center = m_spheres[0].position();
  else
    return Vector3f::Zero();

  m_centerDirty = false;

  if (m_spheres.size() == 1)
    return m_center;

  for (size_t i = 1; i < m_spheres.size(); ++i)
    m_center += m_spheres[i].position();
  m_center /= static_cast<float>(m_spheres.size());

  return m_center;
}

float Scene::radius() const
{
  // Just need an approximate radius, so only looking at max in any dimension.
  m_radius = 5.0;
  center();
  for (size_t i = 0; i < m_spheres.size(); ++i)
    for (int j = 0; j < 3; ++j)
      if (std::abs(m_center(j) - m_spheres[i].position()(j)) > m_radius)
        m_radius = std::abs(m_center(j) - m_spheres[i].position()(j));
  return m_radius;
}

void Scene::addSphere(const Vector3f &position, const Vector3ub &color,
                      float r, const Primitive::Identifier &id)
{
  // These are here to create the impostor quads that will be acted on by the
  // shaders. If we used geometry shaders we could create just one vertex etc.
  unsigned int index = static_cast<unsigned int>(m_sphereVertices.size());

  // Use our packed data structure...
  ColorTextureVertex vert(position, color, Vector2f(-r, -r));
  m_sphereVertices.push_back(vert);
  vert.textureCoord = Vector2f(-r, r);
  m_sphereVertices.push_back(vert);
  vert.textureCoord = Vector2f( r,-r);
  m_sphereVertices.push_back(vert);
  vert.textureCoord = Vector2f( r, r);
  m_sphereVertices.push_back(vert);

  // 6 indexed vertices to draw a quad...
  m_sphereIndices.push_back(index + 0);
  m_sphereIndices.push_back(index + 1);
  m_sphereIndices.push_back(index + 2);
  m_sphereIndices.push_back(index + 3);
  m_sphereIndices.push_back(index + 2);
  m_sphereIndices.push_back(index + 1);

  m_spheres.push_back(Sphere(position, r, id, color));

  m_centerDirty = true;
  m_dirty = true;
}

void Scene::addCylinder(const Vector3f &position1, const Vector3f &direction,
                        float length, float radius_, const Vector3ub &color,
                        const Primitive::Identifier &id)
{
  m_cylinders.push_back(Cylinder(position1, direction, length, radius_, id,
                                 color));

  const unsigned int resolution = 12; // points per circle
  const float resRadians =
      2.0f * static_cast<float>(M_PI) / static_cast<float>(resolution);

  const Vector3f position2 = position1 + direction * length;

  // Generate the radial vectors
  Vector3f radial = direction.unitOrthogonal() * radius_;
  Eigen::AngleAxisf transform(resRadians, direction);
  std::vector<Vector3f> radials;
  radials.reserve(resolution);
  for (unsigned int i = 0; i < resolution; ++i) {
    radials.push_back(radial);
    radial = transform * radial;
  }

  // Generate the vertices:
  //   Endcap1
  const unsigned int end1Start =
      static_cast<unsigned int>(m_cylinderVertices.size());
  ColorNormalVertex vert(color, -direction, position1);
  m_cylinderVertices.push_back(vert);
  for (std::vector<Vector3f>::const_iterator it = radials.begin(),
       itEnd = radials.end(); it != itEnd; ++it) {
    vert.vertex = position1 + *it;
    m_cylinderVertices.push_back(vert);
  }

  //   Endcap2
  const unsigned int end2Start =
      static_cast<unsigned int>(m_cylinderVertices.size());
  vert.normal = direction;
  vert.vertex = position2;
  m_cylinderVertices.push_back(vert);
  for (std::vector<Vector3f>::const_iterator it = radials.begin(),
       itEnd = radials.end(); it != itEnd; ++it) {
    vert.vertex = position2 + *it;
    m_cylinderVertices.push_back(vert);
  }

  //   Tube
  const unsigned int tubeStart =
      static_cast<unsigned int>(m_cylinderVertices.size());
  for (std::vector<Vector3f>::const_iterator it = radials.begin(),
       itEnd = radials.end(); it != itEnd; ++it) {
    vert.normal = *it;
    vert.vertex = position1 + *it;
    m_cylinderVertices.push_back(vert);
    vert.vertex = position2 + *it;
    m_cylinderVertices.push_back(vert);
  }

  // stitch the cylinder together:
  for (unsigned int i = 0; i < resolution; ++i) {
    unsigned int j = (i != 0 ? i : resolution);
    //   Endcap1
    m_cylinderIndices.push_back(end1Start);
    m_cylinderIndices.push_back(end1Start + i + 1);
    m_cylinderIndices.push_back(end1Start + j);

    //   Endcap2
    m_cylinderIndices.push_back(end2Start);
    m_cylinderIndices.push_back(end2Start + j);
    m_cylinderIndices.push_back(end2Start + i + 1);
  }

  for (unsigned int i = 0; i < resolution; ++i) {
    unsigned int r1 = i + i;
    unsigned int r2 = (i != 0 ? r1 : resolution + resolution) - 2;
    m_cylinderIndices.push_back(tubeStart + r1);
    m_cylinderIndices.push_back(tubeStart + r1 + 1);
    m_cylinderIndices.push_back(tubeStart + r2);

    m_cylinderIndices.push_back(tubeStart + r2);
    m_cylinderIndices.push_back(tubeStart + r1 + 1);
    m_cylinderIndices.push_back(tubeStart + r2 + 1);
  }

  m_centerDirty = true;
  m_dirty = true;
}

void Scene::addTriangles(const Vector3f *vertices, const Vector3f *normals,
                         size_t n)
{
  for (size_t i = 0; i < n; ++i) {
    m_triangleMesh.push_back(ColorNormalVertex(Vector3ub(255, 0, 0),
                                               *normals++,
                                               *vertices++));
    m_triangleIndices.push_back(static_cast<unsigned int>(i));
  }
  m_dirty = true;
  std::cout << m_triangleMesh.size() << " triangles added to the scene" << std::endl;
}

void Scene::clear()
{
  m_spheres.clear();
  m_sphereIndices.clear();
  m_sphereVertices.clear();
  m_cylinders.clear();
  m_cylinderIndices.clear();
  m_cylinderVertices.clear();
  m_triangleMesh.clear();
  m_triangleIndices.clear();
  m_centerDirty = true;
  m_dirty = true;
}

} // End Rendering namespace
} // End Avogadro namespace
