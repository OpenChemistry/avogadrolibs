/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "lennardjones.h"
#include "avogadro/core/avogadrocore.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <cmath>

namespace Avogadro::Calc {

namespace {
Real evaluateLennardJonesPairs(const Eigen::VectorXd& x,
                               const Eigen::MatrixXd& radii,
                               Core::UnitCell* cell, Real depth, int exponent,
                               Eigen::VectorXd* grad)
{
  const Index numAtoms = radii.rows();
  Real energy = 0.0;

  for (Index i = 0; i < numAtoms; ++i) {
    const Vector3 ipos = x.segment<3>(3 * i);
    for (Index j = i + 1; j < numAtoms; ++j) {
      const Vector3 jpos = x.segment<3>(3 * j);
      Vector3 delta = Vector3::Zero();
      Real r = 0.0;

      if (cell == nullptr) {
        delta = ipos - jpos;
        r = delta.norm();
      } else if (grad != nullptr) {
        delta = cell->minimumImage(ipos - jpos);
        r = delta.norm();
      } else {
        r = cell->distance(ipos, jpos);
      }

      if (r < 0.1)
        r = 0.1; // ensure we don't divide by zero

      const Real ratio = std::pow(radii(i, j) / r, exponent);
      energy += depth * (ratio * ratio - 2.0 * ratio);

      if (grad == nullptr)
        continue;

      // dE/dr for E = depth * ((sigma/r)^(2n) - 2 * (sigma/r)^n)
      const Real dEdr =
        -2.0 * depth * static_cast<Real>(exponent) * ratio * (ratio - 1.0) / r;
      const Vector3 force = (dEdr / r) * delta;
      grad->segment<3>(3 * i) += force;
      grad->segment<3>(3 * j) -= force;
    }
  }

  return energy;
}
} // namespace

LennardJones::LennardJones()
  : m_molecule(nullptr), m_cell(nullptr), m_radii(), m_vdw(true),
    m_depth(100.0), m_exponent(6), m_elements()
{
  // defined for 1-118
  for (unsigned int i = 1; i <= 118; ++i) {
    m_elements.set(i);
  }
}

void LennardJones::setMolecule(Core::Molecule* mol)
{
  m_molecule = mol;

  if (mol == nullptr) {
    return; // nothing to do
  }

  m_mask = mol->frozenAtomMask();

  m_cell = mol->unitCell(); // could be nullptr
  Index numAtoms = mol->atomCount();

  // track atomic radii for this molecule
  m_radii.setZero();
  Eigen::MatrixXd radii(numAtoms, numAtoms);
  Eigen::MatrixXd mask(numAtoms * 3, 1);
  mask.setOnes();
  m_mask = mask;

  for (Index i = 0; i < numAtoms; ++i) {
    Core::Atom atom1 = mol->atom(i);
    unsigned char number1 = atom1.atomicNumber();
    double r1;
    if (m_vdw)
      r1 = Core::Elements::radiusVDW(number1);
    else
      r1 = Core::Elements::radiusCovalent(number1);

    for (Index j = i + 1; j < numAtoms; ++j) {
      Core::Atom atom2 = mol->atom(j);
      unsigned char number2 = atom2.atomicNumber();
      double r2;
      if (m_vdw)
        r2 = Core::Elements::radiusVDW(number2);
      else
        r2 = Core::Elements::radiusCovalent(number2);

      radii(i, j) = r1 + r2; // expected distance
    }
  }

  m_radii = radii;
}

Real LennardJones::value(const Eigen::VectorXd& x)
{
  return evaluate(x, nullptr);
}

void LennardJones::gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  evaluate(x, &grad);
}

Real LennardJones::evaluate(const Eigen::VectorXd& x, Eigen::VectorXd* grad)
{
  if (grad != nullptr) {
    if (grad->rows() != x.rows())
      grad->resize(x.rows());
    grad->setZero();
  }

  if (!m_molecule ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return 0.0;

  Real energy =
    evaluateLennardJonesPairs(x, m_radii, m_cell, m_depth, m_exponent, grad);
  energy += constraintEnergies(x);

  if (grad != nullptr) {
    cleanGradients(*grad);
    constraintGradients(x, *grad);
  }

  return energy;
}

} // namespace Avogadro::Calc
