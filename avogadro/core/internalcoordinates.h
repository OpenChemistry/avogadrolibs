/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_INTERNALCOORDINATES_H
#define AVOGADRO_CORE_INTERNALCOORDINATES_H

#include "array.h"
#include "avogadrocore.h"
#include "vector.h"

namespace Avogadro {
namespace Core {

/** A simple struct to define internal / z-matrix coordinates. */
struct InternalCoordinate
{
  Index a;
  Index b;
  Index c;
  Real length;
  Real angle;
  Real dihedral;
};

Array<Vector3> internalToCartesian(
  const Molecule& molecule, const Array<InternalCoordinate>& internalCoords);

Array<InternalCoordinate> cartesianToInternal(const Molecule& molecule);

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_INTERNALCOORDINATES_H
