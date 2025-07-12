/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "energycalculator.h"

#include <iostream>
#include <avogadro/core/angletools.h>

using Eigen::Vector3d;

namespace Avogadro::Calc {

void EnergyCalculator::gradient(const TVector& x, TVector& grad)
{
  finiteGradient(x, grad);
  // clean and handle frozen atoms
  cleanGradients(grad);
  // add any constraints
  constraintGradients(x, grad);
}

void EnergyCalculator::cleanGradients(TVector& grad)
{
  unsigned int size = grad.rows();
  // check for overflows -- in case of divide by zero, etc.
  for (unsigned int i = 0; i < size; ++i) {
    if (!std::isfinite(grad[i]) || std::isnan(grad[i])) {
      grad[i] = 0.0;
    }
  }

  // freeze any masked atoms or coordinates
  if (m_mask.rows() == size)
    grad = grad.cwiseProduct(m_mask);
  else
    std::cerr << "Error: mask size " << m_mask.rows() << " " << grad.rows()
              << std::endl;
}

void EnergyCalculator::setConstraints(
  const Core::Array<Core::Constraint>& constraints)
{
  m_distanceConstraints.clear();
  m_angleConstraints.clear();
  m_torsionConstraints.clear();
  m_outOfPlaneConstraints.clear();

  for (const auto& constraint : constraints) {
    switch (constraint.type()) {
      case Core::Constraint::DistanceConstraint:
        m_distanceConstraints.push_back(constraint);
        break;
      case Core::Constraint::AngleConstraint:
        m_angleConstraints.push_back(constraint);
        break;
      case Core::Constraint::TorsionConstraint:
        m_torsionConstraints.push_back(constraint);
        break;
      case Core::Constraint::OutOfPlaneConstraint:
        m_outOfPlaneConstraints.push_back(constraint);
        break;
      default:
        std::cerr << "Unknown constraint type: " << constraint.type()
                  << std::endl;
    }
  }
}

Core::Array<Core::Constraint> EnergyCalculator::constraints() const
{
  Index totalSize = m_distanceConstraints.size() + m_angleConstraints.size() +
                    m_torsionConstraints.size() +
                    m_outOfPlaneConstraints.size();
  Core::Array<Core::Constraint> allConstraints;
  allConstraints.reserve(totalSize);

  for (const auto& constraint : m_distanceConstraints)
    allConstraints.push_back(constraint);

  for (const auto& constraint : m_angleConstraints)
    allConstraints.push_back(constraint);

  for (const auto& constraint : m_torsionConstraints)
    allConstraints.push_back(constraint);

  for (const auto& constraint : m_outOfPlaneConstraints)
    allConstraints.push_back(constraint);

  return allConstraints;
}

Real EnergyCalculator::constraintEnergies(const TVector& x)
{
  Real totalEnergy = 0.0;

  for (const auto& constraint : m_distanceConstraints) {
    const Index a = constraint.aIndex();
    const Index b = constraint.bIndex();
    if ((3 * a + 2 >= x.size()) || (3 * b + 2 >= x.size()))
      // shouldn't happen - invalid constraint
      continue;

    const Vector3d vA(x[3 * a], x[3 * a + 1], x[3 * a + 2]);
    const Vector3d vB(x[3 * b], x[3 * b + 1], x[3 * b + 2]);
    const Vector3d vAB = vA - vB;
    const Real distance = vAB.norm();
    const Real delta = distance - constraint.value();

    // harmonic restraint
    totalEnergy += constraint.k() * delta * delta;
  }

  for (const auto& constraint : m_angleConstraints) {
    const Index a = constraint.aIndex();
    const Index b = constraint.bIndex();
    const Index c = constraint.cIndex();
    if ((3 * a + 2 >= x.size()) || (3 * b + 2 >= x.size()) ||
        (3 * c + 2 >= x.size()))
      // shouldn't happen, invalid constraint
      continue;

    const Vector3d vA(x[3 * a], x[3 * a + 1], x[3 * a + 2]);
    const Vector3d vB(x[3 * b], x[3 * b + 1], x[3 * b + 2]);
    const Vector3d vC(x[3 * c], x[3 * c + 1], x[3 * c + 2]);
    const Real angle = calculateAngle(vA, vB, vC);
    const Real delta = angle - constraint.value();

    // harmonic restraint
    totalEnergy += constraint.k() * delta * delta;
  }

  for (const auto& constraint : m_torsionConstraints) {
    // Calculate energy for torsion constraints
    // totalEnergy += calculateTorsionEnergy(constraint);
  }

  for (const auto& constraint : m_outOfPlaneConstraints) {
    // Calculate energy for out-of-plane constraints
    // totalEnergy += calculateOutOfPlaneEnergy(constraint);
  }

  return totalEnergy;
}

void EnergyCalculator::constraintGradients(const TVector& x, TVector& grad)
{
  for (const auto& constraint : m_distanceConstraints) {
    const Index a = constraint.aIndex();
    const Index b = constraint.bIndex();
    if ((3 * a + 2 >= x.size()) || (3 * b + 2 >= x.size()))
      // shouldn't happen - invalid constraint
      continue;

    const Vector3d vA(x[3 * a], x[3 * a + 1], x[3 * a + 2]);
    const Vector3d vB(x[3 * b], x[3 * b + 1], x[3 * b + 2]);
    const Vector3d vAB = vA - vB;
    const Real distance = vAB.norm();
    const Real delta = distance - constraint.value();
    const Real dE = constraint.k() * 2 * delta;

    grad[3 * a] += dE * vAB[0];
    grad[3 * a + 1] += dE * vAB[1];
    grad[3 * a + 2] += dE * vAB[2];

    grad[3 * b] -= dE * vAB[0];
    grad[3 * b + 1] -= dE * vAB[1];
    grad[3 * b + 2] -= dE * vAB[2];
  }

  for (const auto& constraint : m_angleConstraints) {
    // TODO
  }

  for (const auto& constraint : m_torsionConstraints) {
    // TODO
  }

  for (const auto& constraint : m_outOfPlaneConstraints) {
    // TODO
  }
}

} // namespace Avogadro::Calc
