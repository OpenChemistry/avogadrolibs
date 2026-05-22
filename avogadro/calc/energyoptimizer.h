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
  Lbfgs,
  Fire2,
  AbcFire
};

struct LbfgsParameters
{
  /// Trust-radius cap on |x_new - x|. Zero disables.
  double maxStep = 0.0;
  /// Strong Wolfe curvature tolerance for the line search.
  double wolfeGtol = 0.9;
};

/// Defaults tuned for kJ/(mol*Angstrom) forces with unit mass per d.o.f.
/// (Avogadro convention). The Guénolé 2020 paper assumes atomistic-MD units
/// (eV/Angstrom, amu masses) and uses larger dt0 / maxMove.
struct FireParameters
{
  double dt0 = 0.05;
  double dtMax = 0.5;
  double alphaStart = 0.25;
  double fAlpha = 0.99;
  double fInc = 1.1;
  double fDec = 0.5;
  int nDelay = 5;
  double maxMove = 0.05;
  double mass = 1.0;
};

struct AVOGADROCALC_EXPORT OptimizationOptions
{
  OptimizationAlgorithm algorithm = OptimizationAlgorithm::Lbfgs;
  size_t chunkIterations = 5;
  LbfgsParameters lbfgs;
  FireParameters fire;
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
