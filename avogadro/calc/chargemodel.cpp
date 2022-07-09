/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "chargemodel.h"

#include <avogadro/core/array.h>
#include <avogadro/core/molecule.h>

namespace Avogadro {

using Core::Array;
using Core::Molecule;

namespace Calc {

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

ChargeModel::ChargeModel() : m_dielectric(1.0) {}

ChargeModel::~ChargeModel() {}

double ChargeModel::potential(Molecule& mol, const Vector3& point) const
{
  // default is to get the set of partial atomic charges
  const MatrixX charges = partialCharges(mol);
  // also get the positions of the atoms
  const Array<Vector3> positions = mol.atomPositions3d();

  // @todo: this is naive and inefficient
  //  calculate the atoms within a cutoff distance
  //  and sum the potentials

  double potential = 0.0;
  for (unsigned int i = 0; i < charges.size(); ++i) {
    double distance = (positions[i] - point).norm();
    if (distance > 0.01) {
      // drop small distances to avoid overflow
      potential += charges(i,0) / distance;
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
  for(unsigned int i = 0; i < points.size(); ++i)
    potentials[i] = potential(mol, points[i]);
  return potentials;
}

void ChargeModel::appendError(const std::string& errorString, bool newLine) const
{
  m_error += errorString;
  if (newLine)
    m_error += "\n";
}

} // namespace Calc
} // namespace Avogadro
