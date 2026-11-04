/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_ENERGYOPTIMIZER_H
#define AVOGADRO_CALC_ENERGYOPTIMIZER_H

#include "avogadrocalcexport.h"

#include <Eigen/Core>

#include <cstddef>
#include <limits>

namespace Avogadro::Calc {

class EnergyCalculator;

enum class OptimizationAlgorithm
{
  Lbfgs,
  Fire2,
  AbcFire,
  /// Drive initial optimization with ABC-FIRE (cheap, robust on bad
  /// geometries) then switch to L-BFGS (better tail convergence) once
  /// |g|_inf falls below HybridParameters::switchGradient. The switch is
  /// one-way; OptimizerState::hybridSwitched records it.
  Hybrid
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

struct HybridParameters
{
  /// |g|_inf threshold at which the Hybrid algorithm hands off from
  /// ABC-FIRE to L-BFGS. Units match the gradient reported by the energy
  /// model (kJ/(mol*Angstrom) for Avogadro's built-in force fields). The
  /// 5.0 default is "FIRE got close, let L-BFGS finish" — tuned on caffeine
  /// / tpy-Ru / 1CRN UFF. Set lower for tighter FIRE-only runs, higher to
  /// let L-BFGS take over sooner.
  double switchGradient = 5.0;
};

struct AVOGADROCALC_EXPORT OptimizationOptions
{
  OptimizationAlgorithm algorithm = OptimizationAlgorithm::Lbfgs;
  size_t chunkIterations = 5;
  LbfgsParameters lbfgs;
  FireParameters fire;
  HybridParameters hybrid;
};

/// Why the last optimizeSteps call returned before using its full budget.
enum class OptimizerStopReason
{
  /// Ran every requested iteration.
  IterationLimit,
  /// L-BFGS stopped making progress (the line search can no longer lower
  /// the energy, typically at the numerical noise floor of the energy
  /// model). More iterations from the same point will not help.
  Stalled
};

/// Optional persistent state for optimizeSteps. Carries FIRE's integrator
/// state (velocity, dt, alpha, nPos) and the L-BFGS correction history across
/// chunks so neither is reset each call. Always populated on successful return
/// with (energy, gradient) at the final positions; callers may use those in
/// place of an extra evaluate() to check convergence.
///
/// Set initialized=false (or default-construct) to restart cleanly. A size
/// mismatch with positions also triggers an internal reset.
struct OptimizerState
{
  Eigen::VectorXd velocity;
  double dt = 0.0;
  double alpha = 0.0;
  int nPos = 0;
  bool initialized = false;

  /// Sticky flag set by the Hybrid algorithm once it has handed off from
  /// ABC-FIRE to L-BFGS. Reset to drive a fresh hybrid run.
  bool hybridSwitched = false;

  double energy = std::numeric_limits<double>::quiet_NaN();
  Eigen::VectorXd gradient;

  /// L-BFGS correction pairs (s = dx, y = dg) as columns, oldest/newest
  /// order given by lbfgsPos and lbfgsCount (a ring buffer once full), and
  /// the H_0 scaling. Empty when there is no history. Only valid for the
  /// positions the last L-BFGS chunk ended at; any other algorithm moving
  /// the positions clears it.
  Eigen::MatrixXd lbfgsS;
  Eigen::MatrixXd lbfgsY;
  size_t lbfgsCount = 0;
  size_t lbfgsPos = 0;
  double lbfgsScaling = 1.0;
  /// Consecutive iterations so far that violated the L-BFGS stall test (no
  /// real step / no energy change). Carried across chunks so the "three in a
  /// row" test does not depend on how the run is cut into chunks. Cleared
  /// together with the history.
  int stallXViolations = 0;
  int stallFViolations = 0;

  /// Filled by every optimizeSteps call: iterations actually performed
  /// (may be fewer than requested) and why the call returned.
  size_t iterationsRun = 0;
  OptimizerStopReason stopReason = OptimizerStopReason::IterationLimit;

  void clearLbfgsHistory()
  {
    lbfgsS.resize(0, 0);
    lbfgsY.resize(0, 0);
    lbfgsCount = 0;
    lbfgsPos = 0;
    lbfgsScaling = 1.0;
    stallXViolations = 0;
    stallFViolations = 0;
  }
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
  const OptimizationOptions& options = OptimizationOptions{},
  OptimizerState* state = nullptr);

/**
 * Propose a chunk size for the next optimizeSteps call so that one chunk
 * fits within a wall-clock budget. Intended for interactive callers that
 * want to refresh the view at a fixed rate (~30 fps) regardless of method
 * cost.
 *
 * Uses multiplicative (log-space) EMA so a 2x speedup and a 2x slowdown
 * move the chunk size by the same amount. With @p smoothing == 1.0 the
 * step is fully reactive (no smoothing); with 0.0 it never changes.
 *
 * Time arguments are doubles in milliseconds so sub-ms chunks (small
 * molecules in a Release build) still drive the chunk size upward; pass
 * @c QElapsedTimer::nsecsElapsed()/1e6 from Qt callers.
 *
 * @param currentChunk  chunk size that produced the measurement
 * @param measuredMs    wall time observed for that chunk (>0 required;
 *                      otherwise @p currentChunk is returned, clamped)
 * @param targetMs      desired wall time per chunk
 * @param smoothing     EMA weight in [0, 1]; 0.7 is a reasonable default
 * @param minChunk      lower clamp (must be >= 1)
 * @param maxChunk      upper clamp
 */
AVOGADROCALC_EXPORT size_t
adaptChunkIterations(size_t currentChunk, double measuredMs, double targetMs,
                     double smoothing, size_t minChunk, size_t maxChunk);

} // namespace Avogadro::Calc

#endif // AVOGADRO_CALC_ENERGYOPTIMIZER_H
