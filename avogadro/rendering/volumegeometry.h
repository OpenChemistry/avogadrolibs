/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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
