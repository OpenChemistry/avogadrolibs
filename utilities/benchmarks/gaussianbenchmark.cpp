/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/core/cube.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/gaussiansettools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/gaussianfchk.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

using Avogadro::Core::BasisSet;
using Avogadro::Core::Cube;
using Avogadro::Core::GaussianSet;
using Avogadro::Core::GaussianSetTools;
using Avogadro::Core::Molecule;
using Avogadro::QuantumIO::GaussianFchk;
using Clock = std::chrono::steady_clock;

struct Options
{
  std::string dataRoot = AVOGADRO_BENCHMARK_DATA_ROOT;
  std::size_t warmup = 1;
  std::size_t iterations = 3;
  float spacing = 0.2f;
  float padding = 3.0f;
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
  std::size_t basisFunctions = 0;
  std::size_t gridPoints = 0;
  TimingStats moTiming;
  TimingStats densityTiming;
  bool success = false;
  std::string error;
};

void printUsage(const char* argv0)
{
  std::cout
    << "Usage: " << argv0
    << " [--data-root PATH] [--warmup N] [--iterations N]"
       " [--spacing F] [--padding F] [fchk files...]\n"
    << "\nBenchmarks GaussianSetTools MO and electron density evaluation.\n"
    << "Default dataset: all fchk files in data/fchk/\n"
    << "\nOptions:\n"
    << "  --spacing F     Grid spacing in Angstroms (default: 0.2)\n"
    << "  --padding F     Padding around molecule in Angstroms (default: "
       "5.0)\n";
}

bool parseUnsigned(const std::string& text, std::size_t& value)
{
  try {
    std::size_t consumed = 0;
    const auto parsed = std::stoull(text, &consumed);
    if (consumed != text.size())
      return false;
    value = static_cast<std::size_t>(parsed);
    return true;
  } catch (...) {
    return false;
  }
}

bool parseFloat(const std::string& text, float& value)
{
  try {
    std::size_t consumed = 0;
    value = std::stof(text, &consumed);
    return consumed == text.size();
  } catch (...) {
    return false;
  }
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
    if (arg == "--spacing") {
      if (i + 1 >= argc || !parseFloat(argv[i + 1], options.spacing)) {
        std::cerr << "Invalid value for --spacing\n";
        return false;
      }
      ++i;
      continue;
    }
    if (arg == "--padding") {
      if (i + 1 >= argc || !parseFloat(argv[i + 1], options.padding)) {
        std::cerr << "Invalid value for --padding\n";
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

  // Default: all fchk files in data/fchk/
  if (options.inputFiles.empty()) {
    options.inputFiles = { "data/fchk/h2o-restricted.fchk",
                           "data/fchk/benzene.fchk",
                           "data/fchk/methane.FChk",
                           "data/fchk/co.fchk",
                           "data/fchk/no2.fchk",
                           "data/fchk/caffeine.fchk",
                           "data/fchk/benzene-tz.fchk",
                           "data/fchk/coronene.fchk",
                           "data/fchk/pentacene.fchk",
                           "data/fchk/c60.fchk" };
  }

  return true;
}

fs::path resolvePath(const std::string& dataRoot, const std::string& file)
{
  const fs::path p(file);
  return p.is_absolute() ? p : fs::path(dataRoot) / p;
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

  // Load molecule and basis set
  GaussianFchk format;
  Molecule molecule;
  if (!format.readFile(moleculePath.string(), molecule)) {
    result.error = "Unable to read fchk file";
    return result;
  }

  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  if (!basis) {
    result.error = "No Gaussian basis set found";
    return result;
  }
  basis->initCalculation();

  result.atoms = molecule.atomCount();
  result.basisFunctions = basis->molecularOrbitalCount();

  // Create GaussianSetTools
  GaussianSetTools tools(&molecule);
  if (!tools.isValid()) {
    result.error = "GaussianSetTools not valid";
    return result;
  }

  // Set up the cube grid
  Cube cube;
  cube.setLimits(molecule, options.spacing, options.padding);
  result.gridPoints = cube.data()->size();

  // Pick the HOMO for MO benchmarking
  int homo = basis->homo();
  if (homo < 0)
    homo = 0;

  std::cout << "  " << result.label << ": " << result.atoms << " atoms, "
            << result.basisFunctions << " BFs, " << result.gridPoints
            << " grid points" << std::flush;

  // --- MO benchmark ---
  // Warm up
  for (std::size_t i = 0; i < options.warmup; ++i)
    tools.calculateMolecularOrbital(cube, homo);

  std::vector<double> moSamples;
  moSamples.reserve(options.iterations);
  for (std::size_t i = 0; i < options.iterations; ++i) {
    auto start = Clock::now();
    tools.calculateMolecularOrbital(cube, homo);
    auto end = Clock::now();
    moSamples.push_back(
      std::chrono::duration<double, std::milli>(end - start).count());
  }
  result.moTiming = computeStats(moSamples);

  // --- Electron density benchmark ---
  // Warm up
  for (std::size_t i = 0; i < options.warmup; ++i)
    tools.calculateElectronDensity(cube);

  std::vector<double> densitySamples;
  densitySamples.reserve(options.iterations);
  for (std::size_t i = 0; i < options.iterations; ++i) {
    auto start = Clock::now();
    tools.calculateElectronDensity(cube);
    auto end = Clock::now();
    densitySamples.push_back(
      std::chrono::duration<double, std::milli>(end - start).count());
  }
  result.densityTiming = computeStats(densitySamples);

  std::cout << " ... done\n";
  result.success = true;
  return result;
}

void printResults(const std::vector<BenchmarkResult>& results,
                  const Options& options)
{
  std::cout << "\n=========================================="
            << "==========================================\n"
            << "GaussianSetTools Benchmark\n"
            << "Data root:  " << options.dataRoot << "\n"
            << "Spacing:    " << options.spacing
            << " A   Padding: " << options.padding << " A\n"
            << "Warmup:     " << options.warmup
            << "   Iterations: " << options.iterations << "\n"
            << "==========================================\n\n";

  // Header
  std::cout << std::left << std::setw(24) << "File" << std::right
            << std::setw(7) << "Atoms" << std::setw(7) << "BFs" << std::setw(12)
            << "Points" << std::setw(14) << "MO(ms)" << std::setw(14)
            << "Density(ms)" << std::setw(14) << "MO/pt(us)" << std::setw(14)
            << "Dens/pt(us)"
            << "\n";
  std::cout << std::string(108, '-') << "\n";

  for (const auto& r : results) {
    if (!r.success) {
      std::cout << std::left << std::setw(24) << r.label
                << "  ERROR: " << r.error << "\n";
      continue;
    }

    double moPerPoint =
      (r.gridPoints > 0) ? (r.moTiming.medianMs * 1000.0 / r.gridPoints) : 0;
    double densPerPoint = (r.gridPoints > 0)
                            ? (r.densityTiming.medianMs * 1000.0 / r.gridPoints)
                            : 0;

    std::cout << std::left << std::setw(24) << r.label << std::right
              << std::setw(7) << r.atoms << std::setw(7) << r.basisFunctions
              << std::setw(12) << r.gridPoints << std::fixed
              << std::setprecision(1) << std::setw(14) << r.moTiming.medianMs
              << std::setw(14) << r.densityTiming.medianMs
              << std::setprecision(3) << std::setw(14) << moPerPoint
              << std::setw(14) << densPerPoint << "\n";
  }

  // Summary totals
  double totalMo = 0.0, totalDensity = 0.0;
  std::size_t totalPoints = 0;
  for (const auto& r : results) {
    if (r.success) {
      totalMo += r.moTiming.medianMs;
      totalDensity += r.densityTiming.medianMs;
      totalPoints += r.gridPoints;
    }
  }
  std::cout << std::string(108, '-') << "\n";
  std::cout << std::left << std::setw(24) << "TOTAL" << std::right
            << std::setw(7) << "" << std::setw(7) << "" << std::setw(12)
            << totalPoints << std::fixed << std::setprecision(1)
            << std::setw(14) << totalMo << std::setw(14) << totalDensity
            << "\n\n";
}

} // namespace

int main(int argc, char** argv)
{
  Options options;
  if (!parseArgs(argc, argv, options))
    return 1;

  std::cout << "Running GaussianSetTools benchmarks...\n";

  std::vector<BenchmarkResult> results;
  results.reserve(options.inputFiles.size());
  for (const auto& file : options.inputFiles)
    results.push_back(
      benchmarkFile(resolvePath(options.dataRoot, file), options));

  printResults(results, options);

  const bool anyFailure =
    std::any_of(results.begin(), results.end(),
                [](const BenchmarkResult& r) { return !r.success; });
  return anyFailure ? 2 : 0;
}
