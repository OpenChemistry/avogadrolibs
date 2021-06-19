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

#ifndef AVOGADRO_RENDERING_TRANSFORMNODE_H
#define AVOGADRO_RENDERING_TRANSFORMNODE_H

#include "groupnode.h"

namespace Avogadro {
namespace Rendering {

/**
 * @class TransformNode transformnode.h <avogadro/rendering/transformnode.h>
 * @brief The TransformNode class applies a transform to all child nodes.
 * @author Marcus D. Hanwell
 *
 * @todo This is currently a stub and does nothing.
 */

class AVOGADRORENDERING_EXPORT TransformNode : public GroupNode
{
public:
  explicit TransformNode(GroupNode* parent = nullptr);
  ~TransformNode() override;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_TRANSFORMNODE_H
