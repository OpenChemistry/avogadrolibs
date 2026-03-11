/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_ENERGYOPTIMIZER_H
#define AVOGADRO_CALC_ENERGYOPTIMIZER_H

#include "avogadrocalcexport.h"

#include <Eigen/Core>

#include <cstddef>

namespace Avogadro::Calc {

class EnergyCalculator;

enum class OptimizationAlgorithm
{
  Lbfgs
};

struct AVOGADROCALC_EXPORT OptimizationOptions
{
  OptimizationAlgorithm algorithm = OptimizationAlgorithm::Lbfgs;
  size_t chunkIterations = 5;
};

/**
 * Run a bounded number of optimization iterations on the current position
 * vector.
 *
 * @return true if the selected algorithm was executed, false if options are
 * invalid or unsupported.
 */
AVOGADROCALC_EXPORT bool optimizeSteps(
  EnergyCalculator& method, Eigen::VectorXd& positions,
  const OptimizationOptions& options = OptimizationOptions{});

} // namespace Avogadro::Calc

#endif // AVOGADRO_CALC_ENERGYOPTIMIZER_H
