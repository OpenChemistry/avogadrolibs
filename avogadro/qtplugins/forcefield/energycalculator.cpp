/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "energycalculator.h"

#include <QtCore/QDebug>

namespace Avogadro {

void EnergyCalculator::gradient(const TVector& x, TVector& grad)
{
  finiteGradient(x, grad);
  cleanGradients(grad);
}

void EnergyCalculator::cleanGradients(Eigen::VectorXd& grad)
{
  unsigned int size = grad.rows();
  for (unsigned int i = 0; i < size; ++i) {
    if (!isfinite(grad[i])) {
      grad[i] = 0.0;
    }

    //@todo handle constraints (e.g., frozen atoms)
  }
}

} // namespace Avogadro
