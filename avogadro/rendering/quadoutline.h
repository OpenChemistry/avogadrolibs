/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_QUADOUTLINE_H
#define AVOGADRO_RENDERING_QUADOUTLINE_H

#include "linestripgeometry.h"

#include <avogadro/core/array.h>

namespace Avogadro {
namespace Rendering {

/**
 * @class QuadOutline quadoutline.h
 * <avogadro/rendering/quadoutline.h>
 * @brief The QuadOutline class is a convenience class for creating a
 * quadrilateral outline as a LineStripGeometry.
 */
class AVOGADRORENDERING_EXPORT QuadOutline : public LineStripGeometry
{
public:
  QuadOutline() {}
  ~QuadOutline() override {}

  /**
   * @brief setQuad Set the four corners of the quad.
   */
  void setQuad(const Vector3f& topLeft, const Vector3f& topRight,
               const Vector3f& bottomLeft, const Vector3f& bottomRight,
               float lineWidth);
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_QUADOUTLINE_H
