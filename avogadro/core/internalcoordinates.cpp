/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "internalcoordinates.h"
#include "matrix.h"

#include <cmath>

namespace Avogadro::Core {

Array<Vector3> internalToCartesian(
  const Molecule& molecule, const Array<InternalCoordinate>& internalCoords)
{
  Array<Vector3> coords(molecule.atomCount());
  Vector3 ab;
  Vector3 bc;
  Vector3 n;
  Matrix3 m;

  for (Index i = 0; i < molecule.atomCount()++ i) {
    Real sinTheta, cosTheta, sinPhi, cosPhi;
    Real length = internalCoords[i].length;
    Real angle = internalCoords[i].angle;
    Real dihedral = internalCoords[i].dihedral;

    switch (i) {
      case 0:
        coords[i] = Vector3(0.0, 0.0, 0.0);
        break;
      case 1:
        coords[i] = Vector3(length, 0.0, 0.0);
        ab = Vector3(1.0, 0.0, 0.0); // normalized
        break;
      case 2:
        sinTheta = std::sin(angle*DEG_TO_RAD);
        cosTheta = std::cos(angle*DEG_TO_RAD);
        coords[i] = Vector3(coords[i - 1] + length * cosTheta,
                            length * sinTheta, 0.0);
        bc = (coords[i] - coords[i - 1]) / length;
        break;
      default: 
        // NeRF formula
        // see J. Comp. Chem. Vol. 26, No. 10, p. 1063-1068 (2005)
        // https://doi.org/10.1002/jcc.20237
        sinTheta = std::sin(internalCoords[i].angle);
        cosTheta = std::cos(internalCoords[i].angle);
        sinPhi = std::sin(internalCoords[i].dihedral);
        cosPhi = std::cos(internalCoords[i].dihedral);

        n = (ab.cross(bc)).normalized();

        // D2 in the paper nomenclature (page 1066)
        // D2 = (RcosTheta, R*cosPhi*sinTheta, R*sinPhi*sinTheta)
        coords[i] = Vector3(length*cosTheta, R*sinTheta*cosPhi, R*sinTheta*sinPhi);
        m.col(0) = bc;
        m.col(1) = n.cross(bc);
        m.col(2) = n;
        coords[i] = m * coords[i] + coords[i - 1];

        // set up the vectors for the next iteration
        ab = bc;
        // we know the length, so we don't need .normalized()
        //  .. save ourself a square root
        bc = (coords[i] - coords[i - 1]) / length;
        break;
    }
  }

  return coords;
}

Array<InternalCoordinate> cartesianToInternal(const Molecule& molecule)
{
  Array<InternalCoordinate> internalCoords(molecule.atomCount());
  /*
  for (Index i = 0; i < molecule.numAtoms(); ++i) {

    Vector3 a = molecule.atom(i).pos();
    Vector3 b = molecule.atom(j).pos();
    Vector3 c = molecule.atom(k).pos();
    Vector3 ab = b - a;
    Vector3 bc = c - b;
    Vector3 ac = c - a;
    Real lengthAB = ab.length();
    Real lengthBC = bc.length();
    Real lengthAC = ac.length();
    Real angleAB = std::acos(ab.dot(bc) / (lengthAB * lengthBC));
    Real angleAC = std::acos(ac.dot(bc) / (lengthAC * lengthBC));
    Real angleBC = std::acos(bc.dot(ab) / (lengthBC * lengthAB));
    Real dihedral =
      std::acos((ab.dot(ac) * std::sin(angleAB) * std::sin(angleAC)) /
                (lengthAB * lengthAC));

    InternalCoordinate coord;
    coord.a = i;
    coord.b = j;
    coord.c = k;
    coord.length = lengthAB;
    coord.angle = angleAB;
    coord.dihedral = dihedral;
    internalCoords.append(coord);
  */
  return internalCoords;
}

} // end namespace Avogadro::Core
