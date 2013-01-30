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

#include "geometrynode.h"

namespace Avogadro {
namespace Rendering {

GeometryNode::GeometryNode(Node *p) : Node(p), m_renderer(NULL)
{
}

GeometryNode::~GeometryNode()
{
}

void GeometryNode::render(const Camera &)
{
}

} // End namespace Rendering
} // End namespace Avogadro
