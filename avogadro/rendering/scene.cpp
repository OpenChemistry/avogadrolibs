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

#include "geometryvisitor.h"

#include <Eigen/Geometry>

namespace Avogadro {
namespace Rendering {

Scene::Scene()
  : m_backgroundColor(0, 0, 0, 0), m_dirty(true), m_center(Vector3f::Zero()),
    m_radius(4.0f)
{
}

Scene::~Scene()
{
}

Vector3f Scene::center()
{
  if (!m_dirty)
    return m_center;

  GeometryVisitor visitor;
  m_rootNode.accept(visitor);

  // For an empty scene ensure that a minimum radius of 4.0 (gives space).
  m_center = visitor.center();
  m_radius = std::max(4.0f, visitor.radius()) + 2.0f;
  m_dirty = false;

  return m_center;
}

float Scene::radius()
{
  if (!m_dirty)
    return m_radius;

  // We need to know where the center is to get the radius
  center();
  return m_radius;
}

void Scene::clear()
{
  m_rootNode.clear();
  m_dirty = true;
}

} // End Rendering namespace
} // End Avogadro namespace
