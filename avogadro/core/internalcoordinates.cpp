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
        sinTheta = std::sin(angle * DEG_TO_RAD);
        cosTheta = std::cos(angle * DEG_TO_RAD);
        coords[i] =
          Vector3(coords[i - 1] + length * cosTheta, length * sinTheta, 0.0);
        bc = (coords[i] - coords[i - 1]) / length;
        break;
      default:
        // NeRF formula
        // see J. Comp. Chem. Vol. 26, No. 10, p. 1063-1068 (2005)
        // https://doi.org/10.1002/jcc.20237
        sinTheta = std::sin(angle);
        cosTheta = std::cos(angle);
        sinPhi = std::sin(dihedral);
        cosPhi = std::cos(dihedral);

        n = (ab.cross(bc)).normalized();

        // D2 in the paper nomenclature (page 1066)
        // D2 = (RcosTheta, R*cosPhi*sinTheta, R*sinPhi*sinTheta)
        coords[i] = Vector3(length * cosTheta, R * sinTheta * cosPhi,
                            R * sinTheta * sinPhi);
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

  // special cases
  if (molecule.atomCount() < 1)
    return internalCoords;

  // first atom is always at the origin
  InternalCoordinate coord;
  internalCoords.append(coord);
  // so we can go to the next atom
  if (molecule.atomCount() < 2)
    return internalCoords;

  // second atom is along the x-axis
  coord.a = 0;
  coord.b = 1;
  Vector3 ab = molecule.atom(1).pos() - molecule.atom(0).pos();
  coord.length = ab.length();
  internalCoords.append(coord);

  // third atom is the angle
  if (molecule.atomCount() < 3)
    return internalCoords;
  coord.a = 0;
  coord.b = 1;
  coord.c = 2;
  Vector3 bc = molecule.atom(2).pos() - molecule.atom(1).pos();
  coord.length = bc.length();
  coord.angle =
    std::acos(ab.dot(bc) / (coord.length * ab.length())) * RAD_TO_DEG;
  internalCoords.append(coord);

  if (molecule.atomCount() < 4)
    return internalCoords;

  Index j = 2;
  Index k = 1;
  for (Index i = 3; i < molecule.numAtoms(); ++i) {
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
    coord.angle = angleAB * RAD_TO_DEG;
    coord.dihedral = dihedral * RAD_TO_DEG;
    internalCoords.append(coord);

    // set up the vectors for the next iteration
    k = j;
    j = i;
  }
  return internalCoords;
}

} // end namespace Avogadro::Core
