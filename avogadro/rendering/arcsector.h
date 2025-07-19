/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_ARCSECTOR_H
#define AVOGADRO_RENDERING_ARCSECTOR_H

#include "meshgeometry.h"

#include <avogadro/core/array.h>

namespace Avogadro {
namespace Rendering {

/**
 * @class ArcSector arcsector.h
 * <avogadro/rendering/arcsector.h>
 * @brief The ArcSector class is a convenience class for creating an arc
 *  disk (e.g., part of a circle) from a MeshGeometry.
 * @see ArcStrip for the edge of a circle.
 */
class AVOGADRORENDERING_EXPORT ArcSector : public MeshGeometry
{
public:
  ArcSector() {}
  ~ArcSector() override {}

  /**
   * Define the sector.
   * @param origin Center of the circle from which the arc is cut.
   * @param startEdge A vector defining an leading edge of the sector. The
   * direction is used to fix the sector's rotation about the origin, and the
   * length defines the radius of the sector.
   * @param normal The normal direction to the plane of the sector.
   * @param degreesCCW The extent of the sector, measured counter-clockwise from
   * startEdge in degrees.
   * @param resolutionDeg The radial width of each triangle used in the sector
   * approximation in degrees. This will be adjusted to fit an integral number
   * of triangles in the sector. Smaller triangles (better approximations) are
   * chosen if adjustment is needed.
   */
  void setArcSector(const Vector3f& origin, const Vector3f& startEdge,
                    const Vector3f& normal, float degreesCCW,
                    float resolutionDeg);
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_ARCSECTOR_H
