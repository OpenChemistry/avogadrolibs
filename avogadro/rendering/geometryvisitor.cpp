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

#include "spheregeometry.h"

namespace Avogadro {
namespace Rendering {

GeometryVisitor::GeometryVisitor() : m_center(Vector3f::Zero()), m_radius(5)
{
}

GeometryVisitor::~GeometryVisitor()
{
}

void GeometryVisitor::visit(Drawable &)
{
}

void GeometryVisitor::visit(SphereGeometry &geometry)
{
  const std::vector<SphereColor> &spheres = geometry.spheres();
  m_center = Vector3f::Zero();
  if (!spheres.size())
    return;

  // First find the center of the sphere geometry.
  std::vector<SphereColor>::const_iterator it = spheres.begin();
  for (; it != spheres.end(); ++it)
    m_center += it->center;
  m_center /= spheres.size();

  // Now find its radius.
  m_radius = 2.0f; // Minumim radius to be used.
  if (spheres.size() < 2)
    return;
  for (it = spheres.begin(); it != spheres.end(); ++it) {
    float distance = (it->center - m_center).squaredNorm();
    if (distance > m_radius)
      m_radius = distance;
  }
  m_radius = sqrt(m_radius);
}

} // End namespace Rendering
} // End namespace Avogadro
