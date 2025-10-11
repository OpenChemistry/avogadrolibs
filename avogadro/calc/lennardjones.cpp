/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "lennardjones.h"
#include "avogadro/core/avogadrocore.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

namespace Avogadro::Calc {

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
  if (!m_molecule)
    return 0.0;

  // FYI https://en.wikipedia.org/wiki/Lennard-Jones_potential
  //@todo handle unit cells and minimum distances
  Index numAtoms = m_molecule->atomCount();

  Real energy = 0.0;
  // we put the conditional here outside the double loop
  if (m_cell == nullptr) {
    // regular molecule
    for (Index i = 0; i < numAtoms; ++i) {
      Vector3 ipos(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      for (Index j = i + 1; j < numAtoms; ++j) {
        Vector3 jpos(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
        Real r = (ipos - jpos).norm();
        if (r < 0.1)
          r = 0.1; // ensure we don't divide by zero

        Real ratio = pow((m_radii(i, j) / r), m_exponent);
        energy += m_depth * (ratio * ratio - 2.0 * (ratio));
      }
    }
  } else {
    // use the unit cell to get minimum distances
    for (Index i = 0; i < numAtoms; ++i) {
      Vector3 ipos(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      for (Index j = i + 1; j < numAtoms; ++j) {
        Vector3 jpos(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
        Real r = m_cell->distance(ipos, jpos);
        if (r < 0.1)
          r = 0.1; // ensure we don't divide by zero

        Real ratio = pow((m_radii(i, j) / r), m_exponent);
        energy += m_depth * (ratio * ratio - 2.0 * (ratio));
      }
    }
  }

  // qDebug() << " lj: " << energy;
  energy += constraintEnergies(x);
  return energy;
}

void LennardJones::gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule)
    return;

  // clear the gradients
  grad.setZero();

  Index numAtoms = m_molecule->atomCount();
  // we put the conditional here outside the double loop
  if (m_cell == nullptr) {
    // regular molecule
    for (Index i = 0; i < numAtoms; ++i) {
      Vector3 ipos(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      for (Index j = i + 1; j < numAtoms; ++j) {
        Vector3 jpos(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
        Vector3 force = ipos - jpos;

        Real r = force.norm();
        if (r < 0.1)
          r = 0.1; // ensure we don't divide by zero

        Real rad = pow(m_radii(i, j), m_exponent);
        Real term1 = -2 * (m_exponent)*rad * rad * pow(r, -2 * m_exponent - 1);
        Real term2 = 2 * (m_exponent)*rad * pow(r, -1 * m_exponent - 1);
        Real dE = m_depth * (term1 + term2);

        force = (dE / r) * force;

        // update gradients
        for (unsigned int c = 0; c < 3; ++c) {
          grad[3 * i + c] += force[c];
          grad[3 * j + c] -= force[c];
        }
      }
    }
  } else {
    // unit cell
    for (Index i = 0; i < numAtoms; ++i) {
      Vector3 ipos(x[3 * i], x[3 * i + 1], x[3 * i + 2]);
      for (Index j = i + 1; j < numAtoms; ++j) {
        Vector3 jpos(x[3 * j], x[3 * j + 1], x[3 * j + 2]);
        Vector3 force = m_cell->minimumImage(ipos - jpos);

        Real r = force.norm();
        if (r < 0.1)
          r = 0.1; // ensure we don't divide by zero

        Real rad = pow(m_radii(i, j), m_exponent);
        Real term1 = -2 * (m_exponent)*rad * rad * pow(r, -2 * m_exponent - 1);
        Real term2 = 2 * (m_exponent)*rad * pow(r, -1 * m_exponent - 1);
        Real dE = m_depth * (term1 + term2);

        force = (dE / r) * force;

        // update gradients
        for (unsigned int c = 0; c < 3; ++c) {
          grad[3 * i + c] += force[c];
          grad[3 * j + c] -= force[c];
        }
      }
    }
  }

  // handle any constraints
  cleanGradients(grad);
  constraintGradients(x, grad);
}

} // namespace Avogadro::Calc
