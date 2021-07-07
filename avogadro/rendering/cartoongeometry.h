/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_CARTOON_H
#define AVOGADRO_RENDERING_CARTOON_H

#include "bsplinegeometry.h"

namespace Avogadro {
namespace Rendering {
class AVOGADRORENDERING_EXPORT Cartoon : public BSplineGeometry
{
public:
  Cartoon();
  static const float ELIPSE_RATIO;

protected:
  std::vector<ColorNormalVertex> computeCirclePoints(const Eigen::Affine3f& a,
                                                     const Eigen::Affine3f& b,
                                                     float radius,
                                                     bool flat) override;
};
} // namespace Rendering
} // namespace Avogadro

#endif
