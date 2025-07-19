/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "arcstrip.h"

namespace Avogadro::Rendering {

void ArcStrip::setArc(const Vector3f& origin, const Vector3f& start,
                      const Vector3f& normal, float degreesCCW,
                      float resolutionDeg, float lineWidth)
{
  // Prepare rotation, calculate sizes
  const auto resolution =
    static_cast<unsigned int>(std::fabs(std::ceil(degreesCCW / resolutionDeg)));
  const auto numVerts = static_cast<size_t>(resolution + 1);
  const float stepAngleRads =
    (degreesCCW / static_cast<float>(resolution)) * DEG_TO_RAD_F;
  const Eigen::AngleAxisf rot(stepAngleRads, normal);

  // Generate vertices
  Core::Array<Vector3f> verts(numVerts);
  auto vertsInserter(verts.begin());
  auto vertsEnd(verts.end());
  Vector3f radial = start;
  *(vertsInserter++) = origin + radial;
  while (vertsInserter != vertsEnd)
    *(vertsInserter++) = origin + (radial = rot * radial);

  clear();
  addLineStrip(verts, lineWidth);
}

} // End namespace Avogadro::Rendering
