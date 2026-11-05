/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_BSPLINEGEOMETRY_H
#define AVOGADRO_RENDERING_BSPLINEGEOMETRY_H

#include "curvegeometry.h"

namespace Avogadro {
namespace Rendering {

class AVOGADRORENDERING_EXPORT BSplineGeometry : public CurveGeometry
{
public:
  using CurveGeometry::CurveGeometry;

protected:
  /**
   * Uniform quadratic B-spline (C1) with the end control points doubled, so
   * that the curve runs from the first to the last control point.
   */
  Vector3f computeSegmentPoint(size_t segment, float f,
                               const std::vector<Point>& points) const override;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif
