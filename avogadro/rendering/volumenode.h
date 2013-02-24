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

#ifndef AVOGADRO_RENDERING_VOLUMENODE_H
#define AVOGADRO_RENDERING_VOLUMENODE_H

#include "geometrynode.h"

namespace Avogadro {
namespace Rendering {

/**
 * @class VolumeNode volumenode.h <avogadro/rendering/volumenode.h>
 * @brief The VolumeNode class contains a regularly spaced volumetric data set.
 * @author Marcus D. Hanwell
 */

class AVOGADRORENDERING_EXPORT VolumeNode : public GeometryNode
{
public:
  explicit VolumeNode();
  ~VolumeNode();
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_VOLUMENODE_H
