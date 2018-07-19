/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "lennardjones.h"

namespace Avogadro {
namespace QtGui {

LennardJones::LennardJones(QObject* parent_)
: ForceField(parent_),  m_vdw(true), m_depth(100.0), m_exponent(6)
{
}


LennardJones::~LennardJones()
{
}

void LennardJones::setMolecule(QtGui::RWMolecule* mol)
{
  m_molecule = mol;

  if (mol == nullptr) {
    return; // nothing to do
  }
  int numAtoms = mol->atomCount();
  Dim = 3*numAtoms;

  // track atomic radii for this molecule
  m_radii.clear();
  MatrixXd radii(numAtoms, numAtoms);

  for (Index i = 0; i < numAtoms; ++i) {
    Core::Atom atom1 = mol.atom(i);
    unsigned char number1 = atom1.atomicNumber();
    double r1;
    if (m_vdw)
      r1 = Elements::radiusVDW(number1);
    else
      r1 = Elements::radiusCovalent(number1);

    for (Index j = i + 1; j < numAtoms; ++j) {
      Core::Atom atom2 = mol.atom(j);
      unsigned char number2 = atom2.atomicNumber();
      double r2;
      if (m_vdw)
        r2 = Elements::radiusVDW(number2);
      else
        r2 = Elements::radiusCovalent(number2);

      radii(i, j) = r1 + r2;
    }
  }

  m_radii = radii;
  //@todo store unit cell if available
}

Real LennardJones::calculateEnergy() const
{
  if (!m_molecule)
    return 0.0;

  return calculateEnergy(m_molecule->atomPositions3d());
}

Real LennardJones::calculateEnergy(const Core::Array<Vector3>&positions) const
{
  if (!m_molecule)
    return 0.0;

  // FYI https://en.wikipedia.org/wiki/Lennard-Jones_potential
  //@todo handle unit cells and minimum distances
  int numAtoms = mol->atomCount();

  Real energy = 0.0;
  for (Index i = 0; i < numAtoms; ++i) {
    Vector3 ipos = positions3d[i];
    for (Index j = i + 1; j < numAtoms; ++j) {
      Vector3 jpos = positions3d[j];
      Real r = (ipos - jpos).norm(); // save the sqrt
      Real ratio = (m_radii(i,j) / r)**m_exponent;
      energy += m_depth*( ratio**2 - 2.0*(ratio) );
    }
  }

  return energy;
}

//@todo implement gradients

} // namespace QtGui
} // namespace Avogadro
