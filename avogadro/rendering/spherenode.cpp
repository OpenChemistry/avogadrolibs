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

#include "spherenode.h"

namespace Avogadro {
namespace Rendering {

SphereNode::SphereNode(Node *p) : GeometryNode(p)
{
}

SphereNode::~SphereNode()
{
}

void SphereNode::addSphere(const Vector3f &position, const Vector3ub &color,
                           float radius)
{
  m_spheres.push_back(SphereColor(position, radius, color));
}

void SphereNode::clear()
{
  m_spheres.clear();
  m_indices.clear();
}

} // End namespace Rendering
} // End namespace Avogadro
