/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "energyoptimizer.h"

#include "energycalculator.h"

#include <cppoptlib/function.h>
#include <cppoptlib/solver/lbfgs.h>
#include <cppoptlib/solver/progress.h>

#include <algorithm>
#include <cmath>

namespace Avogadro::Calc {

namespace {
class EnergyObjective : public cppoptlib::function::FunctionCRTP<
                          EnergyObjective, double,
                          cppoptlib::function::DifferentiabilityMode::First>
{
public:
  explicit EnergyObjective(EnergyCalculator& method_) : method(method_) {}

  ScalarType operator()(const VectorType& x, VectorType* grad) const
  {
    return method.evaluate(x, grad);
  }

private:
  EnergyCalculator& method;
};

bool optimizeLbfgs(EnergyCalculator& method, Eigen::VectorXd& positions,
                   size_t chunkIterations, const LbfgsParameters& params,
                   OptimizerState* state)
{
  EnergyObjective objective(method);
  cppoptlib::solver::Lbfgs<EnergyObjective> solver;

  if (params.maxStep > 0.0)
    solver.SetMaxStep(params.maxStep);
  if (params.wolfeGtol > 0.0)
    solver.SetWolfeGtol(params.wolfeGtol);

  using StateType = cppoptlib::function::FunctionState<double>;
  // Reuse the cached (energy, gradient) from a prior chunk to skip the
  // bootstrap evaluation cppoptlib would otherwise do at the start of
  // Minimize. Valid when the gradient size matches positions and the
  // cached energy is finite.
  StateType initialState =
    (state && state->gradient.size() == positions.size() &&
     std::isfinite(state->energy))
      ? StateType(positions, state->energy, state->gradient)
      : StateType(positions);
  auto stopProgress =
    cppoptlib::solver::DefaultStoppingSolverProgress<EnergyObjective,
                                                     StateType>();

  stopProgress.num_iterations = chunkIterations;
  stopProgress.x_delta = 0.0;
  stopProgress.f_delta = 0.0;
  stopProgress.gradient_norm = 0.0;
  stopProgress.condition_hessian = 0.0;
  solver.stopping_progress = stopProgress;

  auto [solution, solverProgress] = solver.Minimize(objective, initialState);
  (void)solverProgress;
  positions = solution.x;

  if (state) {
    state->energy = solution.value;
    state->gradient = std::move(solution.gradient);
    // L-BFGS moved positions; any cached FIRE velocity is stale.
    state->velocity.resize(0);
    state->dt = 0.0;
    state->alpha = 0.0;
    state->nPos = 0;
    state->initialized = false;
  }
  return true;
}

// FIRE2 / ABC-FIRE driver. Gradient is evaluated at the *end* of each
// iteration (not the start) so the persisted state carries (energy,
// gradient) at the final positions on exit, and the next chunk can skip
// the bootstrap eval entirely. With a valid state on entry, total cost
// is N gradient evals per N-iteration chunk; the bootstrap eval only
// fires on the first call (or on size mismatch / explicit reset).
bool optimizeFire(EnergyCalculator& method, Eigen::VectorXd& positions,
                  size_t chunkIterations, const FireParameters& p,
                  OptimizationAlgorithm algorithm, OptimizerState* state)
{
  const Eigen::Index n = positions.size();
  Eigen::VectorXd v;
  Eigen::VectorXd grad;
  Eigen::VectorXd dr(n);
  double dt;
  double alpha;
  int nPos;
  double lastEnergy;
  const bool biasCorrect = (algorithm == OptimizationAlgorithm::AbcFire);

  const bool restore = state && state->initialized &&
                       state->velocity.size() == n &&
                       state->gradient.size() == n;
  if (restore) {
    v = std::move(state->velocity);
    grad = std::move(state->gradient);
    lastEnergy = state->energy;
    dt = state->dt;
    alpha = state->alpha;
    nPos = state->nPos;
  } else {
    v = Eigen::VectorXd::Zero(n);
    grad.resize(n);
    lastEnergy = method.evaluate(positions, &grad);
    dt = p.dt0;
    alpha = p.alphaStart;
    nPos = 0;
  }

  for (size_t step = 0; step < chunkIterations; ++step) {
    // grad / lastEnergy are at the current positions on every iteration:
    // either restored from state, freshly bootstrapped, or computed at the
    // end of the previous iteration.
    const double power = -grad.dot(v);

    if (power > 0.0) {
      ++nPos;
      if (nPos > p.nDelay) {
        dt = std::min(dt * p.fInc, p.dtMax);
        alpha *= p.fAlpha;
      }
    } else if (power < 0.0) {
      // Always shrink dt on P<0 (matches ASE; gating shrink behind nDelay
      // would starve a stateless per-chunk caller that never reaches nDelay
      // within a chunk). Shrink first, then backtrack with the new dt.
      nPos = 0;
      dt *= p.fDec;
      positions.noalias() -= 0.5 * dt * v;
      alpha = p.alphaStart;
      v.setZero();
    }

    v.noalias() -= (dt / p.mass) * grad;

    const double fNorm = grad.norm();
    if (fNorm > 0.0) {
      const double k = alpha * v.norm() / fNorm;
      v *= (1.0 - alpha);
      v.noalias() -= k * grad;
    }

    // ABC-FIRE bias correction (Echeverri Restrepo et al. 2023).
    if (biasCorrect && nPos > 0) {
      const double bcDenom = 1.0 - std::pow(1.0 - alpha, nPos);
      if (bcDenom > 1e-12)
        v /= bcDenom;
    }

    dr.noalias() = dt * v;
    if (p.maxMove > 0.0 && n >= 3) {
      double scale = 1.0;
      for (Eigen::Index i = 0; i < n; i += 3) {
        const double atomNorm = dr.segment<3>(i).norm();
        if (atomNorm > p.maxMove)
          scale = std::min(scale, p.maxMove / atomNorm);
      }
      if (scale < 1.0) {
        dr *= scale;
        v *= scale; // keep v consistent with the move we actually took
      }
    }

    positions += dr;
    lastEnergy = method.evaluate(positions, &grad);
  }

  if (state) {
    state->velocity = std::move(v);
    state->gradient = std::move(grad);
    state->energy = lastEnergy;
    state->dt = dt;
    state->alpha = alpha;
    state->nPos = nPos;
    state->initialized = true;
  }
  return true;
}
} // namespace

bool optimizeSteps(EnergyCalculator& method, Eigen::VectorXd& positions,
                   const OptimizationOptions& options, OptimizerState* state)
{
  if (options.chunkIterations == 0)
    return false;

  OptimizationAlgorithm dispatch = options.algorithm;
  if (dispatch == OptimizationAlgorithm::Hybrid) {
    // Sticky switch: once L-BFGS has taken over, stay there. Otherwise
    // dispatch ABC-FIRE while |g|_inf >= threshold. Without state we have
    // no gradient to consult, so default to the ABC-FIRE phase.
    bool useFire = !(state && state->hybridSwitched);
    // Only trust the cached gradient when a FIRE chunk populated it at the
    // current problem size; stale/wrong-sized entries must not flip the switch.
    if (useFire && state && state->initialized &&
        state->gradient.size() == positions.size() &&
        state->gradient.cwiseAbs().maxCoeff() < options.hybrid.switchGradient) {
      useFire = false;
      state->hybridSwitched = true;
    }
    dispatch =
      useFire ? OptimizationAlgorithm::AbcFire : OptimizationAlgorithm::Lbfgs;
  }

  switch (dispatch) {
    case OptimizationAlgorithm::Lbfgs:
      return optimizeLbfgs(method, positions, options.chunkIterations,
                           options.lbfgs, state);
    case OptimizationAlgorithm::Fire2:
    case OptimizationAlgorithm::AbcFire:
      return optimizeFire(method, positions, options.chunkIterations,
                          options.fire, dispatch, state);
    default:
      return false;
  }
}

} // namespace Avogadro::Calc
