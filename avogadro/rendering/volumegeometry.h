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

#ifndef AVOGADRO_RENDERING_VOLUMEGEOMETRY_H
#define AVOGADRO_RENDERING_VOLUMEGEOMETRY_H

#include "drawable.h"

namespace Avogadro {
namespace Rendering {

/**
 * @class VolumeGeometry volumegeometry.h <avogadro/rendering/volumegeometry.h>
 * @brief The VolumeGeometry class contains a regularly spaced volumetric data
 * set.
 * @author Marcus D. Hanwell
 *
 * @todo This is currently a stub and does nothing.
 */

class AVOGADRORENDERING_EXPORT VolumeGeometry : public Drawable
{
public:
  VolumeGeometry();
  ~VolumeGeometry() override;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_VOLUMEGEOMETRY_H
