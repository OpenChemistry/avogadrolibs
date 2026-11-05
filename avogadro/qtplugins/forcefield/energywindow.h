/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ENERGYWINDOW_H
#define AVOGADRO_QTPLUGINS_ENERGYWINDOW_H

#include <cmath>

namespace Avogadro::QtPlugins {

/**
 * Energy-change convergence test that does not depend on the chunk size.
 *
 * The GUI optimizes in chunks whose size adapts to the frame time, down to a
 * single iteration for large molecules. Testing the energy change once per
 * chunk would let one tiny step end the run. Instead the energy at an anchor
 * is remembered and the test is only made once at least `window` real
 * iterations have passed since then; the anchor then moves to the current
 * point. Chunks of `window` iterations or more form a window of their own,
 * which is the plain per-chunk test.
 */
struct EnergyWindow
{
  /// 10 iterations: long enough that one unusually small step (a line search
  /// that barely moves, an FIRE restart) cannot trigger the test, short
  /// enough to add under ~10 steps of latency on a run that really has
  /// converged. Typical GUI chunks run 5-200 iterations.
  static constexpr unsigned int defaultWindow = 10;

  unsigned int window = defaultWindow;
  bool hasAnchor = false;
  unsigned int anchorIterations = 0;
  double anchorEnergy = 0.0;

  void reset() { hasAnchor = false; }

  /**
   * Record the state after a chunk. @p totalIterations is the number of real
   * iterations run so far in the optimization. Returns true when a window has
   * completed and the mean per-iteration energy change over it is below
   * @p tolerance.
   */
  bool update(unsigned int totalIterations, double energy, double tolerance)
  {
    if (!hasAnchor) {
      // The first chunk only sets the anchor.
      anchor(totalIterations, energy);
      return false;
    }
    if (totalIterations < anchorIterations + window)
      return false;
    const double iterations =
      static_cast<double>(totalIterations - anchorIterations);
    const bool converged =
      std::fabs(energy - anchorEnergy) / iterations < tolerance;
    anchor(totalIterations, energy);
    return converged;
  }

private:
  void anchor(unsigned int totalIterations, double energy)
  {
    hasAnchor = true;
    anchorIterations = totalIterations;
    anchorEnergy = energy;
  }
};

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_ENERGYWINDOW_H
