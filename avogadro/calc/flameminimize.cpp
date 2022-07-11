/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "flameminimize.h"

#include <avogadro/core/elements.h>

#include <cmath>

namespace Avogadro::Calc {

FlameMinimize::FlameMinimize()
  : m_molecule(nullptr), m_calc(nullptr)
{}

void FlameMinimize::setMolecule(Core::Molecule* mol)
{
  m_molecule = mol;

  m_forces.resize(3 * mol->atomCount());
  m_forces.setZero();
  m_velocities.resize(3 * mol->atomCount());
  m_velocities.setZero();
  m_accel.resize(3 * mol->atomCount());
  m_accel.setZero();

  m_invMasses.resize(3 * mol->atomCount());
  m_invMasses.setZero();
  for (unsigned int i = 0; i < mol->atomCount(); ++i) {
    //@todo should this be set to 1.0 amu?
    double scaledMass = log(Core::Elements::mass(mol->atom(i).atomicNumber()));

    m_invMasses[3 * i] = 1.0 / scaledMass;
    m_invMasses[3 * i + 1] = 1.0 / scaledMass;
    m_invMasses[3 * i + 2] = 1.0 / scaledMass;
  }
}

bool FlameMinimize::minimize(EnergyCalculator& calc,
                             Eigen::VectorXd& positions)
{
  if (m_molecule == nullptr)
    return false;

  m_calc = &calc;

  //@todo - set convergence criteria (e.g., max steps, min gradients, energy,
  // etc.)

  double alpha = 0.1;  // start
  double deltaT = 0.1 * 1.0e-15; // fs
  unsigned int positiveSteps = 0;

  m_forces.setZero();
  m_velocities.setZero();
  m_accel.setZero();

  for (unsigned int i = 0; i < 20; ++i) {
    verletIntegrate(positions, deltaT);
    //qDebug() << "vvi forces " << m_forces.norm() << " vel " << m_velocities.norm();

    // Step 1
    double power = m_forces.dot(m_velocities);

    // Step 2
    m_velocities = (1.0 - alpha) * m_velocities + alpha*
                   m_forces.cwiseProduct(m_velocities.cwiseAbs());

    if (power > 0.0) {
      // Step 3
      positiveSteps++;
      if (positiveSteps > 5) {
        deltaT = std::min(1.1 * deltaT, 1.0);
        alpha = 0.99 * alpha;
      }
    } else {
      // Step 4
      positiveSteps = 0;
      deltaT = 0.5 * deltaT;
      m_velocities.setZero();
      alpha = 0.1;
    }

    double Frms = m_forces.norm() / sqrt(positions.rows());
    if (Frms < 1.0e-5)
      break;
  }

  return true;
}

void FlameMinimize::verletIntegrate(Eigen::VectorXd& positions, double deltaT)
{
  // See https://en.wikipedia.org/wiki/Verlet_integration#Velocity_Verlet
  // (as one of many examples)
  if (m_molecule == nullptr || m_calc == nullptr)
    return;

  positions += deltaT * m_velocities + (deltaT * deltaT / 2.0) * m_accel;
  m_calc->gradient(positions, m_forces);
  m_forces = -1*m_forces;
  // F = m * a  ==> a = F/m
  // use coefficient-wise product from Eigen
  //  see http://eigen.tuxfamily.org/dox/group__TutorialArrayClass.html
  Eigen::VectorXd newAccel(3 * m_molecule->atomCount());
  newAccel = m_forces.cwiseProduct(m_invMasses);
  m_velocities += 0.5 * deltaT * (m_accel + newAccel);
  m_accel = newAccel;
}

} // namespace Avogadro
