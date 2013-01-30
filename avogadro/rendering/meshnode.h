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

#ifndef AVOGADRO_RENDERING_MESHNODE_H
#define AVOGADRO_RENDERING_MESHNODE_H

#include "geometrynode.h"

namespace Avogadro {
namespace Rendering {

/**
 * @class MeshNode meshnode.h <avogadro/rendering/meshnode.h>
 * @brief The MeshNode class contains a triangular mesh.
 * @author Marcus D. Hanwell
 *
 * This node is capable of rendering a well-formed triangular mesh, which can
 * be all one color, or specify points per vertex. The mesh will be rendered
 * in one call, the normals are expected to be normalized.
 */

class AVOGADRORENDERING_EXPORT MeshNode : public GeometryNode
{
public:
  explicit MeshNode(Node *parent = 0);
  ~MeshNode();
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_MESHNODE_H
