/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/calc/energycalculator.h>
#include <avogadro/calc/uff.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/fileformatmanager.h>

#include "benchmark_common.h"

#include <cppoptlib/function.h>
#include <cppoptlib/solver/conjugated_gradient_descent.h>
#include <cppoptlib/solver/lbfgs.h>
#include <cppoptlib/solver/progress.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

using Avogadro::Real;
using Avogadro::Benchmarks::isPdbFile;
using Avogadro::Benchmarks::parseDouble;
using Avogadro::Benchmarks::parseUnsigned;
using Avogadro::Benchmarks::readMoleculeFromPath;
using Avogadro::Benchmarks::resolvePath;
using Avogadro::Benchmarks::sanitizePdbInput;
using Avogadro::Calc::UFF;
using Avogadro::Core::Molecule;
using Clock = std::chrono::steady_clock;

struct Options
{
  std::string dataRoot = AVOGADRO_BENCHMARK_DATA_ROOT;
  std::size_t warmup = 5;
  std::size_t iterations = 20;
  std::size_t maxOptIterations = 500;
  double gradientTolerance = 1.0e-2;
  std::vector<std::string> inputFiles;
};

struct TimingStats
{
  double medianMs = 0.0;
  double meanMs = 0.0;
  double p95Ms = 0.0;
};

struct BenchmarkResult
{
  std::string label;
  std::size_t atoms = 0;
  TimingStats fused;
  TimingStats separate;
  double speedup = 0.0;
  Real energyDifference = 0.0;
  double gradientMaxAbsDifference = 0.0;
  double checksum = 0.0;
  bool success = false;
  std::string error;
};

void printUsage(const char* argv0)
{
  std::cout << "Usage: " << argv0
            << " [--data-root PATH] [--warmup N] [--iterations N]"
               " [--max-opt-iter N] [--grad-tol VALUE]"
               " [relative/or/absolute molecule files...]\n"
            << "Default dataset includes:\n"
            << "  data/cjson/caffeine.cjson\n"
            << "  data/sdf/tpy-Ru.sdf\n"
            << "  data/pdb/1CRN.pdb\n"
            << "  data/pdb/1MYK.pdb\n"
            << "  data/pdb/1FDT.pdb\n";
}

bool parseArgs(int argc, char** argv, Options& options)
{
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      printUsage(argv[0]);
      return false;
    }
    if (arg == "--data-root") {
      if (i + 1 >= argc) {
        std::cerr << "Missing value for --data-root\n";
        return false;
      }
      options.dataRoot = argv[++i];
      continue;
    }
    if (arg == "--warmup") {
      if (i + 1 >= argc || !parseUnsigned(argv[i + 1], options.warmup)) {
        std::cerr << "Invalid value for --warmup\n";
        return false;
      }
      ++i;
      continue;
    }
    if (arg == "--iterations") {
      if (i + 1 >= argc || !parseUnsigned(argv[i + 1], options.iterations)) {
        std::cerr << "Invalid value for --iterations\n";
        return false;
      }
      ++i;
      continue;
    }
    if (arg == "--max-opt-iter") {
      if (i + 1 >= argc ||
          !parseUnsigned(argv[i + 1], options.maxOptIterations)) {
        std::cerr << "Invalid value for --max-opt-iter\n";
        return false;
      }
      ++i;
      continue;
    }
    if (arg == "--grad-tol") {
      if (i + 1 >= argc ||
          !parseDouble(argv[i + 1], options.gradientTolerance) ||
          options.gradientTolerance <= 0.0) {
        std::cerr << "Invalid value for --grad-tol\n";
        return false;
      }
      ++i;
      continue;
    }

    options.inputFiles.push_back(arg);
  }

  if (options.iterations == 0) {
    std::cerr << "--iterations must be > 0\n";
    return false;
  }

  if (options.maxOptIterations == 0) {
    std::cerr << "--max-opt-iter must be > 0\n";
    return false;
  }

  if (options.inputFiles.empty()) {
    options.inputFiles = { "data/cjson/caffeine.cjson", "data/sdf/tpy-Ru.sdf",
                           "data/pdb/1CRN.pdb", "data/pdb/1MYK.pdb",
                           "data/pdb/1FDT.pdb" };
  }

  return true;
}

TimingStats computeStats(const std::vector<double>& samplesMs)
{
  TimingStats stats;
  if (samplesMs.empty())
    return stats;

  std::vector<double> sorted(samplesMs);
  std::sort(sorted.begin(), sorted.end());

  const std::size_t n = sorted.size();
  if (n % 2 == 0)
    stats.medianMs = (sorted[n / 2 - 1] + sorted[n / 2]) * 0.5;
  else
    stats.medianMs = sorted[n / 2];

  const double sum =
    std::accumulate(sorted.begin(), sorted.end(), 0.0, std::plus<double>());
  stats.meanMs = sum / static_cast<double>(n);

  const std::size_t p95Index =
    static_cast<std::size_t>(std::ceil(0.95 * static_cast<double>(n))) - 1;
  stats.p95Ms = sorted[std::min(p95Index, n - 1)];

  return stats;
}

BenchmarkResult benchmarkFile(const fs::path& moleculePath,
                              const Options& options)
{
  BenchmarkResult result;
  result.label = moleculePath.filename().string();

  if (!fs::exists(moleculePath)) {
    result.error = "File not found: " + moleculePath.string();
    return result;
  }

  Molecule molecule;
  if (!readMoleculeFromPath(moleculePath, molecule)) {
    result.error = "Unable to load molecule via FileFormatManager";
    return result;
  }

  result.atoms = molecule.atomCount();
  if (result.atoms < 2) {
    result.error = "Molecule has fewer than 2 atoms";
    return result;
  }

  UFF uff;
  uff.setMolecule(&molecule);

  const auto positionsArray = molecule.atomPositions3d();
  Eigen::Map<const Eigen::VectorXd> x(positionsArray[0].data(),
                                      3 * result.atoms);

  Eigen::VectorXd fusedGradient = Eigen::VectorXd::Zero(x.size());
  Eigen::VectorXd separateGradient = Eigen::VectorXd::Zero(x.size());

  const Real separateEnergy = uff.value(x);
  uff.gradient(x, separateGradient);
  const Real fusedEnergy = uff.evaluate(x, &fusedGradient);
  if (std::isfinite(fusedEnergy) && std::isfinite(separateEnergy)) {
    result.energyDifference = std::fabs(fusedEnergy - separateEnergy);
  } else if (std::isnan(fusedEnergy) && std::isnan(separateEnergy)) {
    // Both paths produced NaN, which is parity in this context.
    result.energyDifference = 0.0;
  } else {
    result.energyDifference = std::numeric_limits<Real>::infinity();
  }
  result.gradientMaxAbsDifference =
    (fusedGradient - separateGradient).cwiseAbs().maxCoeff();

  // Warm-up both paths before timing.
  for (std::size_t i = 0; i < options.warmup; ++i) {
    (void)uff.evaluate(x, &fusedGradient);
    (void)uff.value(x);
    uff.gradient(x, separateGradient);
  }

  std::vector<double> fusedSamplesMs;
  std::vector<double> separateSamplesMs;
  fusedSamplesMs.reserve(options.iterations);
  separateSamplesMs.reserve(options.iterations);
  double checksum = 0.0;

  for (std::size_t i = 0; i < options.iterations; ++i) {
    auto start = Clock::now();
    const Real eFused = uff.evaluate(x, &fusedGradient);
    auto end = Clock::now();
    fusedSamplesMs.push_back(
      std::chrono::duration<double, std::milli>(end - start).count());

    start = Clock::now();
    const Real eSeparate = uff.value(x);
    uff.gradient(x, separateGradient);
    end = Clock::now();
    separateSamplesMs.push_back(
      std::chrono::duration<double, std::milli>(end - start).count());

    if (std::isfinite(eFused))
      checksum += static_cast<double>(eFused);
    if (std::isfinite(eSeparate))
      checksum += static_cast<double>(eSeparate);

    const double fusedNorm = fusedGradient.squaredNorm();
    const double separateNorm = separateGradient.squaredNorm();
    if (std::isfinite(fusedNorm))
      checksum += fusedNorm;
    if (std::isfinite(separateNorm))
      checksum += separateNorm;
  }

  result.fused = computeStats(fusedSamplesMs);
  result.separate = computeStats(separateSamplesMs);
  result.speedup = (result.fused.medianMs > 0.0)
                     ? (result.separate.medianMs / result.fused.medianMs)
                     : 0.0;
  result.checksum = checksum;
  result.success = true;
  return result;
}

class EnergyObjective : public cppoptlib::function::FunctionCRTP<
                          EnergyObjective, double,
                          cppoptlib::function::DifferentiabilityMode::First>
{
public:
  explicit EnergyObjective(Avogadro::Calc::EnergyCalculator& method)
    : m_method(method)
  {
  }

  // Armijo line search (used by CG) calls with a single argument; expose an
  // explicit 1-arg overload so name lookup in the derived class finds it.
  ScalarType operator()(const VectorType& x) const { return m_method.value(x); }

  ScalarType operator()(const VectorType& x, VectorType* grad) const
  {
    return m_method.evaluate(x, grad);
  }

private:
  Avogadro::Calc::EnergyCalculator& m_method;
};

const char* statusName(cppoptlib::solver::Status status)
{
  using S = cppoptlib::solver::Status;
  switch (status) {
    case S::NotStarted:
      return "NotStarted";
    case S::Continue:
      return "Continue";
    case S::IterationLimit:
      return "MaxIter";
    case S::XDeltaViolation:
      return "XDelta";
    case S::FDeltaViolation:
      return "FDelta";
    case S::GradientNormViolation:
      return "GradNorm";
    case S::HessianConditionViolation:
      return "Hessian";
    case S::Finished:
      return "Finished";
  }
  return "Unknown";
}

bool statusConverged(cppoptlib::solver::Status status)
{
  using S = cppoptlib::solver::Status;
  return status == S::GradientNormViolation || status == S::FDeltaViolation ||
         status == S::XDeltaViolation || status == S::Finished;
}

struct OptimizerStats
{
  std::size_t iterations = 0;
  double walltimeMs = 0.0;
  Real finalEnergy = std::numeric_limits<Real>::quiet_NaN();
  double finalGradNorm = 0.0;
  std::string status = "n/a";
  bool converged = false;
};

struct ConvergenceResult
{
  std::string label;
  std::size_t atoms = 0;
  Real initialEnergy = std::numeric_limits<Real>::quiet_NaN();
  OptimizerStats lbfgs;
  OptimizerStats cg;
  bool success = false;
  std::string error;
};

template <class Solver>
OptimizerStats runSolverToConvergence(UFF& uff,
                                      const Eigen::VectorXd& initialPositions,
                                      std::size_t maxIterations,
                                      double gradientTolerance)
{
  EnergyObjective objective(uff);
  Solver solver;

  using StateType = typename Solver::StateType;
  using ProgressType = typename Solver::ProgressType;
  ProgressType stopProgress;
  stopProgress.num_iterations = maxIterations;
  stopProgress.x_delta = 0.0;
  stopProgress.x_delta_violations = 5;
  stopProgress.f_delta = 0.0;
  stopProgress.f_delta_violations = 5;
  stopProgress.gradient_norm = gradientTolerance;
  stopProgress.condition_hessian = 0.0;
  stopProgress.constraint_threshold = 1.0e-5;
  stopProgress.status = cppoptlib::solver::Status::NotStarted;
  solver.stopping_progress = stopProgress;

  StateType initialState(initialPositions);

  const auto start = Clock::now();
  auto [solution, progress] = solver.Minimize(objective, initialState);
  const auto end = Clock::now();

  OptimizerStats stats;
  stats.walltimeMs =
    std::chrono::duration<double, std::milli>(end - start).count();
  stats.iterations = progress.num_iterations;
  Eigen::VectorXd finalGradient = Eigen::VectorXd::Zero(solution.x.size());
  stats.finalEnergy = uff.evaluate(solution.x, &finalGradient);
  stats.finalGradNorm = finalGradient.template lpNorm<Eigen::Infinity>();
  stats.status = statusName(progress.status);
  stats.converged = statusConverged(progress.status);
  return stats;
}

ConvergenceResult convergenceBenchmark(const fs::path& moleculePath,
                                       const Options& options)
{
  ConvergenceResult result;
  result.label = moleculePath.filename().string();

  if (!fs::exists(moleculePath)) {
    result.error = "File not found: " + moleculePath.string();
    return result;
  }

  Molecule molecule;
  if (!readMoleculeFromPath(moleculePath, molecule)) {
    result.error = "Unable to load molecule via FileFormatManager";
    return result;
  }

  result.atoms = molecule.atomCount();
  if (result.atoms < 2) {
    result.error = "Molecule has fewer than 2 atoms";
    return result;
  }

  UFF uff;
  uff.setMolecule(&molecule);

  const auto positionsArray = molecule.atomPositions3d();
  Eigen::Map<const Eigen::VectorXd> initialMap(positionsArray[0].data(),
                                               3 * result.atoms);
  const Eigen::VectorXd initialPositions = initialMap;

  // Touch caches so the first timed run is not skewed by lazy setup.
  Eigen::VectorXd warmGradient = Eigen::VectorXd::Zero(initialPositions.size());
  result.initialEnergy = uff.evaluate(initialPositions, &warmGradient);

  result.lbfgs =
    runSolverToConvergence<cppoptlib::solver::Lbfgs<EnergyObjective>>(
      uff, initialPositions, options.maxOptIterations,
      options.gradientTolerance);
  result.cg = runSolverToConvergence<
    cppoptlib::solver::ConjugatedGradientDescent<EnergyObjective>>(
    uff, initialPositions, options.maxOptIterations, options.gradientTolerance);

  result.success = true;
  return result;
}

void printConvergenceResults(const std::vector<ConvergenceResult>& results,
                             const Options& options)
{
  std::cout << "\nUFF optimizer convergence: L-BFGS vs Conjugate Gradients\n"
            << "Max iterations: " << options.maxOptIterations
            << "  Gradient tolerance (max-abs): " << std::scientific
            << std::setprecision(2) << options.gradientTolerance << "\n\n";

  std::cout << std::left << std::setw(18) << "Molecule" << std::right
            << std::setw(8) << "Atoms"
            << "  " << std::left << std::setw(8) << "Method" << std::right
            << std::setw(8) << "Iters" << std::setw(12) << "Time(ms)"
            << std::setw(16) << "E_final" << std::setw(12) << "|g|max"
            << "  " << std::left << std::setw(10) << "Status"
            << "\n";
  std::cout << std::string(96, '-') << "\n";

  auto printRow = [](const std::string& label, std::size_t atoms,
                     const char* method, const OptimizerStats& stats) {
    std::cout << std::left << std::setw(18) << label << std::right
              << std::setw(8) << atoms << "  " << std::left << std::setw(8)
              << method << std::right << std::setw(8) << stats.iterations
              << std::setw(12) << std::fixed << std::setprecision(3)
              << stats.walltimeMs << std::setw(16) << std::setprecision(4)
              << stats.finalEnergy << std::setw(12) << std::scientific
              << std::setprecision(3) << stats.finalGradNorm << "  "
              << std::left << std::setw(10) << stats.status << "\n";
  };

  for (const auto& result : results) {
    if (!result.success) {
      std::cout << std::left << std::setw(18) << result.label
                << " error: " << result.error << "\n";
      continue;
    }

    printRow(result.label, result.atoms, "Lbfgs", result.lbfgs);
    printRow("", result.atoms, "CG", result.cg);
  }
}

void printResults(const std::vector<BenchmarkResult>& results,
                  const Options& options)
{
  std::cout << "\nUFF fused benchmark\n"
            << "Data root: " << options.dataRoot << "\n"
            << "Warmup: " << options.warmup
            << "  Iterations: " << options.iterations << "\n\n";

  std::cout << std::left << std::setw(12) << "Molecule" << std::right
            << std::setw(8) << "Atoms" << std::setw(14) << "Fused(ms)"
            << std::setw(14) << "Separate(ms)" << std::setw(11) << "Speedup"
            << std::setw(14) << "|dE|" << std::setw(14) << "max|dGrad|"
            << "\n";
  std::cout << std::string(87, '-') << "\n";

  for (const auto& result : results) {
    if (!result.success) {
      std::cout << std::left << std::setw(12) << result.label
                << " error: " << result.error << "\n";
      continue;
    }

    std::cout << std::left << std::setw(12) << result.label << std::right
              << std::setw(8) << result.atoms << std::setw(14) << std::fixed
              << std::setprecision(3) << result.fused.medianMs << std::setw(14)
              << result.separate.medianMs << std::setw(11)
              << std::setprecision(2) << result.speedup << "x" << std::setw(14)
              << std::scientific << std::setprecision(3)
              << result.energyDifference << std::setw(14)
              << result.gradientMaxAbsDifference << "\n";
  }

  const double checksum = std::accumulate(
    results.begin(), results.end(), 0.0,
    [](double sum, const BenchmarkResult& r) { return sum + r.checksum; });
  std::cout << "\nChecksum: " << std::setprecision(10) << checksum << "\n";
}

} // namespace

int main(int argc, char** argv)
{
  Options options;
  if (!parseArgs(argc, argv, options))
    return 1;

  std::vector<BenchmarkResult> results;
  std::vector<ConvergenceResult> convergence;
  results.reserve(options.inputFiles.size());
  convergence.reserve(options.inputFiles.size());
  for (const auto& file : options.inputFiles) {
    const auto path = resolvePath(options.dataRoot, file);
    results.push_back(benchmarkFile(path, options));
    convergence.push_back(convergenceBenchmark(path, options));
  }

  printResults(results, options);
  printConvergenceResults(convergence, options);

  const bool anyFailure =
    std::any_of(results.begin(), results.end(),
                [](const BenchmarkResult& r) { return !r.success; }) ||
    std::any_of(convergence.begin(), convergence.end(),
                [](const ConvergenceResult& r) { return !r.success; });
  return anyFailure ? 2 : 0;
}
