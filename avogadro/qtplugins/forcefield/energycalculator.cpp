/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "energycalculator.h"

namespace Avogadro {

Real EnergyCalculator::value(const TVector& x)
{
  const double *d = x.data();
  m_positions.data() = d;
  return calculateEnergy(m_positions);
}

} // namespace Avogadro
