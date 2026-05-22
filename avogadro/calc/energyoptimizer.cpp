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
                   size_t chunkIterations, const LbfgsParameters& params)
{
  EnergyObjective objective(method);
  cppoptlib::solver::Lbfgs<EnergyObjective> solver;

  if (params.maxStep > 0.0)
    solver.SetMaxStep(params.maxStep);
  if (params.wolfeGtol > 0.0)
    solver.SetWolfeGtol(params.wolfeGtol);

  auto initialState = cppoptlib::function::FunctionState(positions);
  using StateType = decltype(initialState);
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
  return true;
}

// State (velocity, dt, alpha, N_pos) is reset on every call. This handicaps
// FIRE vs L-BFGS when chunkIterations is small (the adaptive timestep can't
// ramp up across chunk boundaries); persistent state is a planned follow-up.
bool optimizeFire(EnergyCalculator& method, Eigen::VectorXd& positions,
                  size_t chunkIterations, const FireParameters& p,
                  OptimizationAlgorithm algorithm)
{
  const Eigen::Index n = positions.size();
  Eigen::VectorXd v = Eigen::VectorXd::Zero(n);
  Eigen::VectorXd grad(n);
  Eigen::VectorXd dr(n);
  double dt = p.dt0;
  double alpha = p.alphaStart;
  int nPos = 0;
  const bool biasCorrect = (algorithm == OptimizationAlgorithm::AbcFire);

  for (size_t step = 0; step < chunkIterations; ++step) {
    method.evaluate(positions, &grad);
    const double power = -grad.dot(v);

    if (power > 0.0) {
      ++nPos;
      if (nPos > p.nDelay) {
        dt = std::min(dt * p.fInc, p.dtMax);
        alpha *= p.fAlpha;
      }
    } else if (power < 0.0) {
      // Always shrink dt on P<0 (matches ASE; gating shrink behind nDelay,
      // as some FIRE2 references do, starves the stateless per-chunk caller
      // since nPos resets every chunk before nDelay is reached). Shrink
      // first, then backtrack with the new dt.
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
  }

  return true;
}
} // namespace

bool optimizeSteps(EnergyCalculator& method, Eigen::VectorXd& positions,
                   const OptimizationOptions& options)
{
  if (options.chunkIterations == 0)
    return false;

  switch (options.algorithm) {
    case OptimizationAlgorithm::Lbfgs:
      return optimizeLbfgs(method, positions, options.chunkIterations,
                           options.lbfgs);
    case OptimizationAlgorithm::Fire2:
    case OptimizationAlgorithm::AbcFire:
      return optimizeFire(method, positions, options.chunkIterations,
                          options.fire, options.algorithm);
    default:
      return false;
  }
}

} // namespace Avogadro::Calc
