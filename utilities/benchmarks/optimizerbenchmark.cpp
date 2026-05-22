/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/calc/energycalculator.h>
#include <avogadro/calc/energyoptimizer.h>
#include <avogadro/calc/uff.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/fileformatmanager.h>

#include "benchmark_common.h"

#include <chrono>
#include <cmath>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

using Avogadro::Real;
using Avogadro::Benchmarks::parseDouble;
using Avogadro::Benchmarks::parseUnsigned;
using Avogadro::Benchmarks::readMoleculeFromPath;
using Avogadro::Benchmarks::resolvePath;
using Avogadro::Calc::OptimizationAlgorithm;
using Avogadro::Calc::OptimizationOptions;
using Avogadro::Calc::optimizeSteps;
using Avogadro::Calc::UFF;
using Avogadro::Core::Molecule;
using Clock = std::chrono::steady_clock;

struct Options
{
  std::string dataRoot = AVOGADRO_BENCHMARK_DATA_ROOT;
  std::size_t chunkIterations = 5;
  std::size_t maxSteps = 500;
  double gradientTolerance = 1.0e-2;
  std::vector<std::string> inputFiles;
};

struct RunResult
{
  std::size_t chunks = 0;
  std::size_t gradientEvals = 0;
  double walltimeMs = 0.0;
  Real initialEnergy = std::numeric_limits<Real>::quiet_NaN();
  Real finalEnergy = std::numeric_limits<Real>::quiet_NaN();
  double initialGradMaxAbs = 0.0;
  double finalGradMaxAbs = 0.0;
  bool converged = false;
  std::string status;
};

struct BenchmarkResult
{
  std::string label;
  std::size_t atoms = 0;
  RunResult lbfgs;
  RunResult fire2;
  RunResult abcFire;
  bool success = false;
  std::string error;
};

void printUsage(const char* argv0)
{
  std::cout << "Usage: " << argv0
            << " [--data-root PATH] [--chunk-iters N] [--max-steps N]"
               " [--grad-tol VALUE]"
               " [relative/or/absolute molecule files...]\n"
            << "Default dataset includes:\n"
            << "  data/cjson/caffeine.cjson\n"
            << "  data/sdf/tpy-Ru.sdf\n"
            << "  data/pdb/1CRN.pdb\n"
            << "Pass data/pdb/1MYK.pdb or data/pdb/1FDT.pdb explicitly to\n"
            << "include the larger proteins.\n";
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
    if (arg == "--chunk-iters") {
      if (i + 1 >= argc ||
          !parseUnsigned(argv[i + 1], options.chunkIterations) ||
          options.chunkIterations == 0) {
        std::cerr << "Invalid value for --chunk-iters\n";
        return false;
      }
      ++i;
      continue;
    }
    if (arg == "--max-steps") {
      if (i + 1 >= argc || !parseUnsigned(argv[i + 1], options.maxSteps) ||
          options.maxSteps == 0) {
        std::cerr << "Invalid value for --max-steps\n";
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

  if (options.inputFiles.empty()) {
    // Default to small/medium molecules: large proteins would dominate
    // runtime since each chunk pays O(N^2) for vdW pair lookup. Pass
    // data/pdb/1MYK.pdb or data/pdb/1FDT.pdb explicitly to bench those.
    options.inputFiles = { "data/cjson/caffeine.cjson", "data/sdf/tpy-Ru.sdf",
                           "data/pdb/1CRN.pdb" };
  }

  return true;
}

// Transparent UFF wrapper that counts gradient evaluations so the benchmark
// can report cost in the metric that matters when the energy model is
// expensive.
class CountingUff : public Avogadro::Calc::EnergyCalculator
{
public:
  explicit CountingUff(UFF& inner) : m_inner(inner) {}

  EnergyCalculator* newInstance() const override { return nullptr; }
  std::string identifier() const override { return m_inner.identifier(); }
  std::string name() const override { return m_inner.name(); }
  std::string description() const override { return m_inner.description(); }
  Molecule::ElementMask elements() const override { return m_inner.elements(); }
  bool acceptsUnitCell() const override { return m_inner.acceptsUnitCell(); }
  bool acceptsIons() const override { return m_inner.acceptsIons(); }
  bool acceptsRadicals() const override { return m_inner.acceptsRadicals(); }
  void setMolecule(Molecule* mol) override { m_inner.setMolecule(mol); }

  Real value(const Eigen::VectorXd& x) override { return m_inner.value(x); }

  void gradient(const Eigen::VectorXd& x, Eigen::VectorXd& g) override
  {
    ++m_gradientCalls;
    m_inner.gradient(x, g);
  }

  Real evaluate(const Eigen::VectorXd& x, Eigen::VectorXd* g) override
  {
    if (g != nullptr)
      ++m_gradientCalls;
    return m_inner.evaluate(x, g);
  }

  std::size_t gradientCalls() const { return m_gradientCalls; }

private:
  UFF& m_inner;
  std::size_t m_gradientCalls = 0;
};

RunResult runOptimizer(UFF& uff, const Eigen::VectorXd& initialPositions,
                       OptimizationAlgorithm algorithm, const Options& options)
{
  RunResult result;

  CountingUff counter(uff);

  Eigen::VectorXd positions = initialPositions;
  Eigen::VectorXd gradient = Eigen::VectorXd::Zero(positions.size());

  // Initial probe goes through the inner UFF so the counter reflects only
  // work the optimizer itself drove.
  result.initialEnergy = uff.evaluate(positions, &gradient);
  result.initialGradMaxAbs = gradient.cwiseAbs().maxCoeff();

  if (result.initialGradMaxAbs < options.gradientTolerance) {
    result.converged = true;
    result.status = "AlreadyConverged";
    result.finalEnergy = result.initialEnergy;
    result.finalGradMaxAbs = result.initialGradMaxAbs;
    return result;
  }

  OptimizationOptions opts;
  opts.algorithm = algorithm;
  opts.chunkIterations = options.chunkIterations;
  // ~0.2 A average per-d.o.f. motion per L-BFGS step. FIRE self-caps via
  // FireParameters::maxMove.
  opts.lbfgs.maxStep = 0.2 * std::sqrt(static_cast<double>(positions.size()));

  const std::size_t maxChunks = options.maxSteps / options.chunkIterations;

  const auto start = Clock::now();
  for (std::size_t chunk = 0; chunk < maxChunks; ++chunk) {
    if (!optimizeSteps(counter, positions, opts)) {
      result.status = "OptimizeFailed";
      break;
    }
    ++result.chunks;

    // Convergence probe uses the inner UFF so the counter isn't inflated.
    const Real energy = uff.evaluate(positions, &gradient);
    result.finalEnergy = energy;
    result.finalGradMaxAbs = gradient.cwiseAbs().maxCoeff();

    if (!std::isfinite(energy) || !positions.allFinite()) {
      result.status = "NonFinite";
      break;
    }

    if (result.finalGradMaxAbs < options.gradientTolerance) {
      result.converged = true;
      result.status = "Converged";
      break;
    }
  }
  const auto end = Clock::now();

  result.walltimeMs =
    std::chrono::duration<double, std::milli>(end - start).count();
  result.gradientEvals = counter.gradientCalls();
  if (result.status.empty())
    result.status = "MaxSteps";

  return result;
}

BenchmarkResult benchmarkFile(const fs::path& moleculePath,
                              const Options& options)
{
  BenchmarkResult result;
  result.label = moleculePath.filename().string();

  Molecule molecule;
  if (!readMoleculeFromPath(moleculePath, molecule)) {
    result.error = "Unable to load " + moleculePath.string();
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

  // Warm UFF's vdW pair cache so the first timed run isn't skewed.
  Eigen::VectorXd warmGradient = Eigen::VectorXd::Zero(initialPositions.size());
  (void)uff.evaluate(initialPositions, &warmGradient);

  result.lbfgs =
    runOptimizer(uff, initialPositions, OptimizationAlgorithm::Lbfgs, options);
  result.fire2 =
    runOptimizer(uff, initialPositions, OptimizationAlgorithm::Fire2, options);
  result.abcFire = runOptimizer(uff, initialPositions,
                                OptimizationAlgorithm::AbcFire, options);
  result.success = true;
  return result;
}

void printResults(const std::vector<BenchmarkResult>& results,
                  const Options& options)
{
  std::cout << "\nOptimizer benchmark on UFF (L-BFGS vs FIRE2 vs ABC-FIRE)\n"
            << "Data root: " << options.dataRoot << "\n"
            << "Chunk: " << options.chunkIterations
            << "  Max steps: " << options.maxSteps
            << "  Gradient tol (max-abs): " << std::scientific
            << std::setprecision(2) << options.gradientTolerance << "\n\n";

  std::cout << std::left << std::setw(18) << "Molecule" << std::right
            << std::setw(6) << "Atoms"
            << "  " << std::left << std::setw(9) << "Method" << std::right
            << std::setw(6) << "Iters" << std::setw(8) << "gEvals"
            << std::setw(8) << "g/iter" << std::setw(10) << "Time(ms)"
            << std::setw(15) << "E_initial" << std::setw(15) << "E_final"
            << std::setw(11) << "|g|max"
            << "  " << std::left << std::setw(12) << "Status"
            << "\n";
  std::cout << std::string(122, '-') << "\n";

  auto printRow = [&](const std::string& label, std::size_t atoms,
                      const char* method, const RunResult& run) {
    const std::size_t iters = run.chunks * options.chunkIterations;
    const double gPerIter = iters > 0 ? static_cast<double>(run.gradientEvals) /
                                          static_cast<double>(iters)
                                      : 0.0;
    std::cout << std::left << std::setw(18) << label << std::right
              << std::setw(6) << atoms << "  " << std::left << std::setw(9)
              << method << std::right << std::setw(6) << iters << std::setw(8)
              << run.gradientEvals << std::setw(8) << std::fixed
              << std::setprecision(2) << gPerIter << std::setw(10)
              << std::setprecision(1) << run.walltimeMs << std::setw(15)
              << std::setprecision(4)
              << (std::isnan(run.initialEnergy) ? 0.0 : run.initialEnergy)
              << std::setw(15) << run.finalEnergy << std::setw(11)
              << std::scientific << std::setprecision(2) << run.finalGradMaxAbs
              << "  " << std::left << std::setw(12) << run.status << "\n";
  };

  for (const auto& result : results) {
    if (!result.success) {
      std::cout << std::left << std::setw(18) << result.label
                << " error: " << result.error << "\n";
      continue;
    }

    printRow(result.label, result.atoms, "L-BFGS", result.lbfgs);
    printRow("", result.atoms, "FIRE2", result.fire2);
    printRow("", result.atoms, "ABC-FIRE", result.abcFire);
  }

  std::cout << "\nSummary (converged runs only):\n";
  auto summarize = [&](const char* method,
                       const RunResult BenchmarkResult::*field) {
    std::size_t converged = 0;
    double totalMs = 0.0;
    std::size_t totalIters = 0;
    for (const auto& r : results) {
      if (!r.success)
        continue;
      const RunResult& run = r.*field;
      if (run.converged) {
        ++converged;
        totalMs += run.walltimeMs;
        totalIters += run.chunks * options.chunkIterations;
      }
    }
    std::cout << "  " << std::left << std::setw(9) << method << "  "
              << converged << "/" << results.size()
              << " converged, total iters: " << totalIters
              << ", total time: " << std::fixed << std::setprecision(1)
              << totalMs << " ms\n";
  };
  summarize("L-BFGS", &BenchmarkResult::lbfgs);
  summarize("FIRE2", &BenchmarkResult::fire2);
  summarize("ABC-FIRE", &BenchmarkResult::abcFire);
}

} // namespace

int main(int argc, char** argv)
{
  Options options;
  if (!parseArgs(argc, argv, options))
    return 1;

  std::vector<BenchmarkResult> results;
  results.reserve(options.inputFiles.size());
  for (const auto& file : options.inputFiles) {
    const auto path = resolvePath(options.dataRoot, file);
    results.push_back(benchmarkFile(path, options));
  }

  printResults(results, options);

  const bool anyFailure =
    std::any_of(results.begin(), results.end(),
                [](const BenchmarkResult& r) { return !r.success; });
  return anyFailure ? 2 : 0;
}
