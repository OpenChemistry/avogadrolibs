/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "energyoptimizer.h"

#include "energycalculator.h"

#include <cppoptlib/function.h>
#include <cppoptlib/solver/lbfgs.h>
#include <cppoptlib/solver/progress.h>

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
                   size_t chunkIterations)
{
  EnergyObjective objective(method);
  cppoptlib::solver::Lbfgs<EnergyObjective> solver;

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
} // namespace

bool optimizeSteps(EnergyCalculator& method, Eigen::VectorXd& positions,
                   const OptimizationOptions& options)
{
  if (options.chunkIterations == 0)
    return false;

  switch (options.algorithm) {
    case OptimizationAlgorithm::Lbfgs:
      return optimizeLbfgs(method, positions, options.chunkIterations);
    default:
      return false;
  }
}

} // namespace Avogadro::Calc
