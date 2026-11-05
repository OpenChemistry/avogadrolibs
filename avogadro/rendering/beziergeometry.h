/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_BEZIERGEOMETRY_H
#define AVOGADRO_RENDERING_BEZIERGEOMETRY_H

#include "curvegeometry.h"

namespace Avogadro {
namespace Rendering {

class AVOGADRORENDERING_EXPORT BezierGeometry : public CurveGeometry
{
public:
  BezierGeometry();

protected:
  /**
   * The Bezier curve of degree n - 1 over all the control points, at t in
   * [0, 1]. Its point at t is a weighted mean of the control points around
   * index t * (n - 1), with a width that grows as sqrt(n t (1 - t)): a loose,
   * smoothed path that runs from the first to the last control point.
   */
  Vector3f computeCurvePoint(float t, const std::vector<Point>& points) const;
  /**
   * Segment k covers the curve where that centre index is within half a
   * control point of k (the first and last segments cover half of that), so
   * the stretch drawn for a residue is the part of the rope that is centred
   * on it.
   */
  Vector3f computeSegmentPoint(size_t segment, float f,
                               const std::vector<Point>& points) const override;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif
