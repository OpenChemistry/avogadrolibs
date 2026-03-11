/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/calc/uff.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/fileformatmanager.h>

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
using Avogadro::Calc::UFF;
using Avogadro::Core::Molecule;
using Clock = std::chrono::steady_clock;

struct Options
{
  std::string dataRoot = AVOGADRO_BENCHMARK_DATA_ROOT;
  std::size_t warmup = 5;
  std::size_t iterations = 20;
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
               " [relative/or/absolute molecule files...]\n"
            << "Default dataset includes:\n"
            << "  data/cjson/caffeine.cjson\n"
            << "  data/sdf/tpy-Ru.sdf\n"
            << "  data/pdb/1CRN.pdb\n"
            << "  data/pdb/1MYK.pdb\n"
            << "  data/pdb/1FDT.pdb\n";
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

    options.inputFiles.push_back(arg);
  }

  if (options.iterations == 0) {
    std::cerr << "--iterations must be > 0\n";
    return false;
  }

  if (options.inputFiles.empty()) {
    options.inputFiles = { "data/cjson/caffeine.cjson", "data/sdf/tpy-Ru.sdf",
                           "data/pdb/1CRN.pdb", "data/pdb/1MYK.pdb",
                           "data/pdb/1FDT.pdb" };
  }

  return true;
}

fs::path resolvePath(const std::string& dataRoot, const std::string& file)
{
  const fs::path p(file);
  return p.is_absolute() ? p : fs::path(dataRoot) / p;
}

bool isPdbFile(const fs::path& path)
{
  std::string ext = path.extension().string();
  std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return ext == ".pdb" || ext == ".ent";
}

std::string sanitizePdbInput(const std::string& input)
{
  std::istringstream stream(input);
  std::ostringstream cleaned;
  std::string line;
  while (std::getline(stream, line)) {
    if (line.rfind("CONECT", 0) == 0)
      continue;

    if ((line.rfind("ATOM", 0) == 0 || line.rfind("HETATM", 0) == 0) &&
        line.size() > 16) {
      const char altLoc = line[16];
      if (altLoc != ' ' && altLoc != 'A')
        continue;
      if (altLoc == 'A')
        line[16] = ' ';
    }

    cleaned << line << '\n';
  }
  return cleaned.str();
}

bool readMoleculeFromPath(const fs::path& moleculePath, Molecule& molecule)
{
  auto& manager = Avogadro::Io::FileFormatManager::instance();
  if (!isPdbFile(moleculePath))
    return manager.readFile(molecule, moleculePath.string());

  std::ifstream file(moleculePath, std::ios::in);
  if (!file)
    return false;

  std::ostringstream buffer;
  buffer << file.rdbuf();
  const std::string sanitized = sanitizePdbInput(buffer.str());
  if (sanitized.empty())
    return false;

  if (manager.readString(molecule, sanitized, "pdb"))
    return true;

  // Fallback to the raw parser path if sanitizing unexpectedly fails.
  return manager.readFile(molecule, moleculePath.string());
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
