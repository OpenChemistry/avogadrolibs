/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_CARTOON_H
#define AVOGADRO_RENDERING_CARTOON_H

#include "bsplinegeometry.h"

#include <avogadro/core/residue.h>

namespace Avogadro {
namespace Rendering {

enum CartoonType
{
  Undefined = -1, // constant small radius
  Body = 0,       // constant big radius
  Arrow = 3,      // arrow head
  Head = 2,       // decreassing
  Tail = 1        // increassing
};

class AVOGADRORENDERING_EXPORT Cartoon : public BSplineGeometry
{
public:
  Cartoon();
  Cartoon(float minRadius, float maxRadius);
  static const float ELIPSE_RATIO;

  void addPoint(const Vector3f& pos, const Vector3ub& color, size_t group,
                size_t id, Core::Residue::SecondaryStructure sec);

protected:
  // create an elipse and adapt it to the affine A
  std::vector<ColorNormalVertex> computeCirclePoints(const Eigen::Affine3f& a,
                                                     const Eigen::Affine3f& b,
                                                     bool flat) const override;

  float computeScale(size_t index, float t, float scale) const override;

  std::vector<std::pair<CartoonType, size_t>> m_type;
  float m_minRadius, m_maxRadius;
};
} // namespace Rendering
} // namespace Avogadro

#endif
