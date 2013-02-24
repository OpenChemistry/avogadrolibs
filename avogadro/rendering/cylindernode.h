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

#ifndef AVOGADRO_RENDERING_CYLINDERNODE_H
#define AVOGADRO_RENDERING_CYLINDERNODE_H

#include "geometrynode.h"

namespace Avogadro {
namespace Rendering {

/**
 * @class CylinderNode cylindernode.h <avogadro/rendering/cylindernode.h>
 * @brief The CylinderNode contains one or more cylinders.
 * @author Marcus D. Hanwell
 */

class AVOGADRORENDERING_EXPORT CylinderNode : public GeometryNode
{
public:
  explicit CylinderNode();
  ~CylinderNode();
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_CYLINDERNODE_H
