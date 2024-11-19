/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "uff.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>

namespace Avogadro::Calc {

UFF::UFF() : d(nullptr)
{
  // defined for 1-102
  for (unsigned int i = 0; i <= 102; ++i) {
    m_elements.set(i);
  }
}

UFF::~UFF() {}

void UFF::setMolecule(Core::Molecule* mol)
{
  m_molecule = mol;

  if (mol == nullptr) {
    return; // nothing to do
  }

  int numAtoms = mol->atomCount();
}

Real UFF::value(const Eigen::VectorXd& x)
{
  if (!m_molecule)
    return 0.0;

  Real energy = 0.0;

  return energy;
}

void UFF::gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule)
    return;

  // clear the gradients
  grad.setZero();

  // handle any constraints
  cleanGradients(grad);
}

} // namespace Avogadro::Calc
