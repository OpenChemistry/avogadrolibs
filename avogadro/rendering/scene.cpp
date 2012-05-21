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

namespace Avogadro {
namespace Rendering {

Scene::Scene() : m_centerDirty(false), m_center(Vector3f::Zero()), m_radius(0.0)
{
}

Scene::~Scene()
{
}

Vector3f Scene::center() const
{
  if (!m_centerDirty)
    return m_center;

  if (m_spherePositions.size() > 0)
    m_center = m_spherePositions[0];
  else
    return Vector3f::Zero();

  m_centerDirty = false;

  if (m_spherePositions.size() == 4)
    return m_center;

  for (size_t i = 4; i < m_spherePositions.size(); i += 4)
    m_center += m_spherePositions[i];
  m_center = m_center / (m_spherePositions.size() / 4.0f);

  return m_center;
}

float Scene::radius() const
{
  // Just need an approximate radius, so only looking at max in any dimesnion.
  m_radius = 5.0;
  center();
  for (size_t i = 0; i < m_spherePositions.size(); i += 4)
    for (int j = 0; j < 3; ++j)
      if (std::abs(m_center(j) - m_spherePositions[i](j)) > m_radius)
        m_radius = std::abs(m_center(j) - m_spherePositions[i](j));
  return m_radius;
}

void Scene::addSphere(const Vector3f &position, const Vector3ub &color,
                      float r)
{
  // These are here to create the impostor quads that will be acted on by the
  // shaders. If we used geometry shaders we could create just one vertex etc.
  unsigned int index = static_cast<unsigned int>(m_spherePositions.size());
  m_spherePositions.push_back(position);
  m_spherePositions.push_back(position);
  m_spherePositions.push_back(position);
  m_spherePositions.push_back(position);
  m_sphereRadii.push_back(Vector2f(-r,-r));
  m_sphereRadii.push_back(Vector2f(-r, r));
  m_sphereRadii.push_back(Vector2f( r,-r));
  m_sphereRadii.push_back(Vector2f( r, r));
  m_sphereColors.push_back(color);
  m_sphereColors.push_back(color);
  m_sphereColors.push_back(color);
  m_sphereColors.push_back(color);

  // Use our packed data structure...
  ColorTextureVertex vert(position, color, Vector2f(-r, -r));
  m_spheres.push_back(vert);
  vert.textureCoord = Vector2f(-r, r);
  m_spheres.push_back(vert);
  vert.textureCoord = Vector2f( r,-r);
  m_spheres.push_back(vert);
  vert.textureCoord = Vector2f( r, r);
  m_spheres.push_back(vert);

  // 6 indexed vertices to draw a quad...
  m_sphereIndices.push_back(index + 0);
  m_sphereIndices.push_back(index + 1);
  m_sphereIndices.push_back(index + 2);
  m_sphereIndices.push_back(index + 3);
  m_sphereIndices.push_back(index + 2);
  m_sphereIndices.push_back(index + 1);
  m_centerDirty = true;
}

} // End Rendering namespace
} // End Avogadro namespace
