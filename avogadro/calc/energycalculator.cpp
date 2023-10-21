/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "energycalculator.h"

#include <iostream>

namespace Avogadro::Calc {

void EnergyCalculator::gradient(const TVector& x, TVector& grad)
{
  finiteGradient(x, grad);
  cleanGradients(grad);
}

void EnergyCalculator::cleanGradients(TVector& grad)
{
  unsigned int size = grad.rows();
  // check for overflows -- in case of divide by zero, etc.
  for (unsigned int i = 0; i < size; ++i) {
    if (!std::isfinite(grad[i])) {
      grad[i] = 0.0;
    }
  }

  // freeze any masked atoms or coordinates
  grad = grad.cwiseProduct(m_mask);
}

} // namespace Avogadro
