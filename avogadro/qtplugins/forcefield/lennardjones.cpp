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


Real LennardJones::calculateEnergy(const Core::Array<Vector3>& positions)
{
  if (!m_molecule)
    return 0.0;

  // FYI https://en.wikipedia.org/wiki/Lennard-Jones_potential
  //@todo handle unit cells and minimum distances
  int numAtoms = positions.size();

  Real energy = 0.0;
  for (Index i = 0; i < numAtoms; ++i) {
    Vector3 ipos = positions[i];
    for (Index j = i + 1; j < numAtoms; ++j) {
      Vector3 jpos = positions[j];
      Real r = (ipos - jpos).norm(); // save the sqrt
      Real ratio = pow((m_radii(i, j) / r), m_exponent);
      qDebug() << " lj: " << r << m_radii(i,j);
      energy += m_depth * (ratio * ratio - 2.0 * (ratio));
    }
  }

  return energy;
}

/*
void calculateGradients(Core::Array<Vector3>& positions,
                        Core::Array<Vector3>& gradients)
{}
//@todo implement gradients
*/

} // namespace Avogadro
