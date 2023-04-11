/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "arcsector.h"

using Avogadro::Core::Array;

namespace Avogadro::Rendering {

void ArcSector::setArcSector(const Vector3f& origin, const Vector3f& startEdge,
                             const Vector3f& normal, float degreesCCW,
                             float resolutionDeg)
{
  // Prepare rotation, calculate sizes
  const auto numTriangles =
    static_cast<unsigned int>(std::fabs(std::ceil(degreesCCW / resolutionDeg)));
  const auto numVerts = static_cast<size_t>(numTriangles + 2);
  const float stepAngleRads =
    (degreesCCW / static_cast<float>(numTriangles)) * DEG_TO_RAD_F;
  const Eigen::AngleAxisf rot(stepAngleRads, normal);

  // Generate normal array
  Array<Vector3f> norms(numVerts, normal);

  // Generate vertices
  Array<Vector3f> verts(numVerts);
  auto vertsInserter(verts.begin());
  auto vertsEnd(verts.end());
  Vector3f radial = startEdge;
  *(vertsInserter++) = origin;
  *(vertsInserter++) = origin + radial;
  while (vertsInserter != vertsEnd)
    *(vertsInserter++) = origin + (radial = rot * radial);

  // Generate indices
  Array<unsigned int> indices(numTriangles * 3);
  auto indexInserter(indices.begin());
  auto indexEnd(indices.end());
  for (unsigned int i = 1; indexInserter != indexEnd; ++i) {
    *(indexInserter++) = 0;
    *(indexInserter++) = i;
    *(indexInserter++) = i + 1;
  }

  clear();
  addVertices(verts, norms);
  addTriangles(indices);
}

} // End namespace Avogadro::Rendering
