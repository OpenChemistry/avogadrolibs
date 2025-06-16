/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "chargemodel.h"

#include <Eigen/src/Core/util/Meta.h>
#include <avogadro/core/array.h>
#include <avogadro/core/molecule.h>

#include <cstddef>
#include <iostream>

namespace Avogadro {

using Core::Array;
using Core::Molecule;

namespace Calc {

#ifndef M_PI
constexpr double M_PI = 3.14159265358979323846;
#endif

Vector3 ChargeModel::dipoleMoment(const Molecule& mol) const
{
  if (mol.atomCount() < 2)
    return Vector3(0.0, 0.0, 0.0);

  // default is to get the set of partial atomic charges
  // (some models might do something more sophisticated)
  const MatrixX charges = partialCharges(mol);
  // also get the positions of the atoms
  const Array<Vector3> positions = mol.atomPositions3d();

  Vector3 dipole(0.0, 0.0, 0.0);
  if (static_cast<std::size_t>(charges.rows()) != positions.size())
    std::cout << "Error: charges " << charges.rows() << " != positions "
              << positions.size() << std::endl;

  for (Eigen::Index i = 0; i < charges.size(); ++i)
    dipole += charges(i, 0) * positions[i];

  dipole *= 4.80320471257; // convert to Debye from electron-Angstrom

  return dipole;
}

double ChargeModel::potential(Molecule& mol, const Vector3& point) const
{
  // default is to get the set of partial atomic charges
  const MatrixX charges = partialCharges(mol);
  // also get the positions of the atoms
  const Array<Vector3> positions = mol.atomPositions3d();

  // @todo: this is naive and inefficient
  //  calculate the atoms within a cutoff distance
  //  and sum the potentials

  // note this is usually multithreaded by the caller
  // but more efficient methods can be implemented
  double potential = 0.0;
  for (unsigned int i = 0; i < charges.size(); ++i) {
    double distance = (positions[i] - point).norm();
    if (distance > 0.01) {
      // drop small distances to avoid overflow
      potential += charges(i, 0) / distance;
    }
  }

  return potential / m_dielectric;
}

Array<double> ChargeModel::potentials(Core::Molecule& mol,
                                      const Array<Vector3>& points) const
{
  // This is naive and slow, but can be re-implemented by methods
  // for batching
  Array<double> potentials(points.size(), 0.0);
  for (unsigned int i = 0; i < points.size(); ++i)
    potentials[i] = potential(mol, points[i]);
  return potentials;
}

void ChargeModel::appendError(const std::string& errorString,
                              bool newLine) const
{
  m_error += errorString;
  if (newLine)
    m_error += "\n";
}

} // namespace Calc
} // namespace Avogadro
