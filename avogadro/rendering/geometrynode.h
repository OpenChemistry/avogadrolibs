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

#ifndef AVOGADRO_RENDERING_GEOMETRYNODE_H
#define AVOGADRO_RENDERING_GEOMETRYNODE_H

#include "node.h"

namespace Avogadro {
namespace Rendering {

class Camera;
class Renderer;

/**
 * @class GeometryNode geometrynode.h <avogadro/rendering/geometrynode.h>
 * @brief The GeometryNode class is the common base of all geometry nodes.
 * @author Marcus D. Hanwell
 *
 * The GeometryNode class is the common base clas for all nodes containing
 * geometry to be rendered to the scene. It provides some common API for
 * geometry properties, and this class is the one that should be derived from
 * to provide new primitives to render.
 */

class AVOGADRORENDERING_EXPORT GeometryNode : public Node
{
public:
  explicit GeometryNode();
  ~GeometryNode();

  virtual void render(const Camera &camera);

protected:
  Renderer *m_renderer;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_GEOMETRYNODE_H
