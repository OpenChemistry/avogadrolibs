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
  Index a = MaxIndex;
  Index b = MaxIndex;
  Index c = MaxIndex;
  Real length = 0.0;
  Real angle = 0.0;
  Real dihedral = 0.0;
};

Array<Vector3> internalToCartesian(
  const Molecule& molecule, const Array<InternalCoordinate>& internalCoords);

Array<InternalCoordinate> cartesianToInternal(const Molecule& molecule);

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_INTERNALCOORDINATES_H
