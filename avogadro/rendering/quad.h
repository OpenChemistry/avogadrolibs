/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_QUAD_H
#define AVOGADRO_RENDERING_QUAD_H

#include "meshgeometry.h"

#include <avogadro/core/array.h>

namespace Avogadro {
namespace Rendering {

/**
 * @class Quad quad.h
 * <avogadro/rendering/quad.h>
 * @brief The Quad class is a convenience class for creating a quadrilateral
 * mesh.
 */
class AVOGADRORENDERING_EXPORT Quad : public MeshGeometry
{
public:
  Quad() {}
  ~Quad() override {}

  /**
   * @brief setQuad Set the four corners of the quad.
   */
  void setQuad(const Vector3f& topLeft, const Vector3f& topRight,
               const Vector3f& bottomLeft, const Vector3f& bottomRight);
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_QUAD_H
