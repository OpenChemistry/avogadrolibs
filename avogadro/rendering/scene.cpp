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

#include <iostream>

namespace Avogadro {
namespace Rendering {

Scene::Scene()
  : m_dirty(false), m_centerDirty(false),
    m_center(Vector3f::Zero()), m_radius(10.0)
{
}

Scene::~Scene()
{
}

Vector3f Scene::center()
{
  GeometryVisitor visitor;
  m_rootNode.accept(visitor);

  m_center = visitor.center();
  m_radius = visitor.radius();

  return m_center;
}

float Scene::radius()
{
  // We need to know where the center is to get the radius
  center();
  return m_radius;
}

void Scene::clear()
{
  m_rootNode.clear();
  m_centerDirty = true;
  m_dirty = true;
}

} // End Rendering namespace
} // End Avogadro namespace
