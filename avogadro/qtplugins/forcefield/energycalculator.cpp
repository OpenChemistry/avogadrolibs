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

void EnergyCalculator::freezeAtom(Index atomId)
{
  if (atomId * 3 <= m_mask.rows() - 3) {
    m_mask[atomId*3] = 0.0;
    m_mask[atomId*3+1] = 0.0;
    m_mask[atomId*3+2] = 0.0;
  }
}

void EnergyCalculator::unfreezeAtom(Index atomId)
{
  if (atomId * 3 <= m_mask.rows() - 3) {
    m_mask[atomId*3] = 1.0;
    m_mask[atomId*3+1] = 1.0;
    m_mask[atomId*3+2] = 1.0;
  }
}

} // namespace Avogadro
