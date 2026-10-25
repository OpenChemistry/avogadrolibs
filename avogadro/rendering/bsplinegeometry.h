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
  BSplineGeometry();
  BSplineGeometry(bool flat);

protected:
  /**
   * Global uniform quadratic B-spline through all control points with one
   * knot interval per control point. @p t in [0, 1] maps onto the
   * points.size() - 2 segments.
   */
  Vector3f computeCurvePoint(float t,
                             const std::vector<Point>& points) const override;
  bool hasUniformSegments() const override { return true; }
  Vector3f computeSegmentPoint(size_t segment, float f,
                               const std::vector<Point>& points) const override;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif
