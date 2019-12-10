/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "lennardjones.h"

#include <avogadro/core/elements.h>

#include <QtCore/QDebug>

namespace Avogadro {

LennardJones::LennardJones(QObject* parent_)
  : EnergyCalculator(parent_)
  , m_vdw(true)
  , m_depth(100.0)
  , m_exponent(6)
{}

LennardJones::~LennardJones() {}

void LennardJones::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;

  if (mol == nullptr) {
    return; // nothing to do
  }
  int numAtoms = mol->atomCount();

  // track atomic radii for this molecule
  m_radii.setZero();
  Eigen::MatrixXd radii(numAtoms, numAtoms);

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
  //@todo store unit cell if available
}

Real LennardJones::value(const Eigen::VectorXd& x)
{
  if (!m_molecule)
    return 0.0;

  // FYI https://en.wikipedia.org/wiki/Lennard-Jones_potential
  //@todo handle unit cells and minimum distances
  int numAtoms = m_molecule->atomCount();

  Real energy = 0.0;
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

  // qDebug() << " lj: " << energy;
  return energy;
}

void LennardJones::gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_molecule)
    return;

  // clear the gradients
  grad.setZero();

  //@todo handle unit cells and minimum distances
  int numAtoms = m_molecule->atomCount();

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

  // handle any constraints
  cleanGradients(grad);
}

} // namespace Avogadro
