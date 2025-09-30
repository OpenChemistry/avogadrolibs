/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_ARCSTRIP_H
#define AVOGADRO_RENDERING_ARCSTRIP_H

#include "linestripgeometry.h"

#include <avogadro/core/array.h>

namespace Avogadro {
namespace Rendering {

/**
 * @class ArcStrip arcstrip.h
 * <avogadro/rendering/arcstrip.h>
 * @brief The ArcStrip class is a convenience class for creating an arc
 *  line (e.g., the edge of a circle).
 */
class AVOGADRORENDERING_EXPORT ArcStrip : public LineStripGeometry
{
public:
  ArcStrip() {}
  ~ArcStrip() override {}

  /**
   * Define the arc.
   * @param origin Center of the circle from which the arc is cut.
   * @param start A vector pointing from the origin to the start of the arc.
   * @param normal The normal direction to the plane of the circle.
   * @param degreesCCW The extent of the arc, measured counter-clockwise from
   * start in degrees.
   * @param resolutionDeg The radial width of each segment used in the arc
   * approximation, in degrees. This will be adjusted to fit an integral number
   * of segments into the arc. Smaller segments (better approximations) are
   * chosen if adjustment is needed.
   * @param lineWidth The width of the line.
   */
  void setArc(const Vector3f& origin, const Vector3f& start,
              const Vector3f& normal, float degreesCCW, float resolutionDeg,
              float lineWidth);
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_ARCSTRIP_H
