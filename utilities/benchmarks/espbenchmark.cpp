/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Benchmark for ChargeModel::potentials() (point-charge electrostatic
// potential), as used to colour surfaces by ESP.
//
// For each workload (molecule x number of points) this compares
//   (a) legacy: a serial loop calling potential() once per point, which
//       refetches the charges and positions on every call (old behaviour)
//   (b) potentials() restricted to one thread
//   (c) potentials() with the default thread count
//   (d) a thread sweep (1, 2, 4, ... hardware_concurrency)
// Thread counts are set through the AVOGADRO_ESP_THREADS environment
// variable, which potentials() reads on each call.

#include <avogadro/calc/chargemodel.h>

#include <avogadro/core/array.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include "benchmark_common.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

using Avogadro::MatrixX;
using Avogadro::Vector3;
using Avogadro::Benchmarks::parseUnsigned;
using Avogadro::Benchmarks::readMoleculeFromPath;
using Avogadro::Benchmarks::resolvePath;
using Avogadro::Calc::ChargeModel;
using Avogadro::Core::Array;
using Avogadro::Core::Molecule;
using Clock = std::chrono::steady_clock;

struct Options
{
  std::string dataRoot = AVOGADRO_BENCHMARK_DATA_ROOT;
  std::size_t repeats = 3;
  // The legacy path is O(points x atoms) with a charge-matrix copy per point;
  // beyond this many pair evaluations it is timed on a prefix of the points
  // and extrapolated.
  std::size_t legacyMaxPairs = 400000000;
  std::vector<std::string> inputFiles;
  std::vector<std::size_t> pointCounts;
};

// Fixed, seeded charges: no external charge model is needed.
class SyntheticChargeModel : public ChargeModel
{
public:
  explicit SyntheticChargeModel(std::size_t atoms)
    : m_charges(static_cast<Eigen::Index>(atoms), 1)
  {
    // portable LCG (std distributions differ between standard libraries)
    std::uint64_t state = 12345;
    for (Eigen::Index i = 0; i < m_charges.rows(); ++i) {
      state = state * 6364136223846793005ULL + 1442695040888963407ULL;
      const double u = static_cast<double>(state >> 11) / 9007199254740992.0;
      m_charges(i, 0) = 0.8 * (u - 0.5);
    }
  }

  ChargeModel* newInstance() const override
  {
    return new SyntheticChargeModel(static_cast<std::size_t>(m_charges.rows()));
  }
  std::string identifier() const override { return "synthetic"; }
  std::string name() const override { return "Synthetic"; }
  Molecule::ElementMask elements() const override
  {
    Molecule::ElementMask mask;
    mask.set();
    return mask;
  }
  MatrixX partialCharges(Molecule&) const override { return m_charges; }
  MatrixX partialCharges(const Molecule&) const override { return m_charges; }

private:
  MatrixX m_charges;
};

void setThreads(std::size_t threads)
{
#ifdef _WIN32
  _putenv_s("AVOGADRO_ESP_THREADS",
            threads > 0 ? std::to_string(threads).c_str() : "");
#else
  if (threads > 0)
    setenv("AVOGADRO_ESP_THREADS", std::to_string(threads).c_str(), 1);
  else
    unsetenv("AVOGADRO_ESP_THREADS");
#endif
}

Array<Vector3> makePoints(const Molecule& molecule, std::size_t count)
{
  const Array<Vector3>& pos = molecule.atomPositions3d();
  Vector3 lo = pos[0], hi = pos[0];
  for (const auto& p : pos) {
    lo = lo.cwiseMin(p);
    hi = hi.cwiseMax(p);
  }
  lo.array() -= 3.0;
  hi.array() += 3.0;

  Array<Vector3> points;
  points.reserve(count);
  std::uint64_t state = 987654321;
  for (std::size_t i = 0; i < count; ++i) {
    Vector3 p;
    for (int k = 0; k < 3; ++k) {
      state = state * 6364136223846793005ULL + 1442695040888963407ULL;
      const double u = static_cast<double>(state >> 11) / 9007199254740992.0;
      p[k] = lo[k] + u * (hi[k] - lo[k]);
    }
    points.push_back(p);
  }
  return points;
}

template <class F>
double medianMs(std::size_t repeats, F&& f)
{
  std::vector<double> samples;
  for (std::size_t i = 0; i < repeats; ++i) {
    const auto start = Clock::now();
    f();
    const auto end = Clock::now();
    samples.push_back(
      std::chrono::duration<double, std::milli>(end - start).count());
  }
  std::sort(samples.begin(), samples.end());
  return samples[samples.size() / 2];
}

void printUsage(const char* argv0)
{
  std::cout << "Usage: " << argv0
            << " [--data-root PATH] [--repeats N] [--points N]..."
               " [--legacy-max-pairs N] [molecule files...]\n"
            << "Default molecules: caffeine.cjson, 1CRN.pdb, 4HHB.pdb\n"
            << "Default point counts: 10000, 100000, 1000000\n"
            << "Thread counts are set via AVOGADRO_ESP_THREADS "
               "(read by ChargeModel::potentials()).\n";
}

bool parseArgs(int argc, char** argv, Options& options)
{
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      printUsage(argv[0]);
      return false;
    }
    if (arg == "--data-root" && i + 1 < argc) {
      options.dataRoot = argv[++i];
    } else if (arg == "--repeats" && i + 1 < argc) {
      if (!parseUnsigned(argv[++i], options.repeats) || options.repeats == 0) {
        std::cerr << "Invalid value for --repeats\n";
        return false;
      }
    } else if (arg == "--legacy-max-pairs" && i + 1 < argc) {
      if (!parseUnsigned(argv[++i], options.legacyMaxPairs)) {
        std::cerr << "Invalid value for --legacy-max-pairs\n";
        return false;
      }
    } else if (arg == "--points" && i + 1 < argc) {
      std::size_t n = 0;
      if (!parseUnsigned(argv[++i], n) || n == 0) {
        std::cerr << "Invalid value for --points\n";
        return false;
      }
      options.pointCounts.push_back(n);
    } else {
      options.inputFiles.push_back(arg);
    }
  }
  if (options.inputFiles.empty())
    options.inputFiles = { "data/cjson/caffeine.cjson", "data/pdb/1CRN.pdb",
                           "data/pdb/4HHB.pdb" };
  if (options.pointCounts.empty())
    options.pointCounts = { 10000, 100000, 1000000 };
  return true;
}

// Returns false on a load failure or a correctness mismatch.
bool runWorkload(const std::string& label, Molecule& molecule,
                 std::size_t pointCount, const Options& options,
                 std::size_t hardware)
{
  const std::size_t atoms = molecule.atomCount();
  SyntheticChargeModel model(atoms);
  const Array<Vector3> points = makePoints(molecule, pointCount);
  const double pairs =
    static_cast<double>(atoms) * static_cast<double>(pointCount);
  // fewer repeats for the very slow cases
  const std::size_t repeats = pairs > 1.0e9 ? 1 : options.repeats;

  std::cout << "\n"
            << label << ": " << atoms << " atoms, " << pointCount << " points ("
            << std::scientific << std::setprecision(2) << pairs
            << " pair evaluations), repeats " << repeats << "\n";

  // (a) legacy path, possibly on a prefix of the points
  std::size_t legacyPoints = pointCount;
  if (static_cast<std::size_t>(pairs) > options.legacyMaxPairs)
    legacyPoints = std::max<std::size_t>(1, options.legacyMaxPairs / atoms);
  legacyPoints = std::min(legacyPoints, pointCount);
  std::vector<double> legacy(legacyPoints, 0.0);
  const double legacyPartialMs = medianMs(repeats, [&]() {
    for (std::size_t i = 0; i < legacyPoints; ++i)
      legacy[i] = model.potential(molecule, points[i]);
  });
  const double legacyMs = legacyPartialMs * static_cast<double>(pointCount) /
                          static_cast<double>(legacyPoints);
  const bool extrapolated = legacyPoints < pointCount;

  // (b) one thread
  setThreads(1);
  Array<double> single;
  const double oneMs =
    medianMs(repeats, [&]() { single = model.potentials(molecule, points); });

  // (c) default thread count
  setThreads(0);
  Array<double> parallel;
  const double defaultMs =
    medianMs(repeats, [&]() { parallel = model.potentials(molecule, points); });

  // correctness: legacy vs default (over the legacy prefix), and (b) vs (c)
  double maxDiff = 0.0;
  for (std::size_t i = 0; i < legacyPoints; ++i)
    maxDiff = std::max(maxDiff, std::fabs(legacy[i] - parallel[i]));
  double maxDiffAll = 0.0;
  for (std::size_t i = 0; i < pointCount; ++i)
    maxDiffAll = std::max(maxDiffAll, std::fabs(single[i] - parallel[i]));

  std::cout << std::fixed << std::setprecision(2);
  std::cout << std::left << std::setw(34) << "Path" << std::right
            << std::setw(12) << "Time(ms)" << std::setw(14) << "vs legacy"
            << std::setw(14) << "vs 1 thread"
            << "\n";
  std::cout << std::string(74, '-') << "\n";
  auto row = [&](const std::string& name, double ms, bool est) {
    std::cout << std::left << std::setw(34) << (name + (est ? " (est.)" : ""))
              << std::right << std::setw(12) << std::fixed
              << std::setprecision(3) << ms << std::setw(13)
              << std::setprecision(2) << legacyMs / ms << "x" << std::setw(13)
              << oneMs / ms << "x\n";
  };
  row("legacy serial potential() loop", legacyMs, extrapolated);
  row("potentials(), 1 thread", oneMs, false);
  row("potentials(), default threads", defaultMs, false);

  // (d) thread sweep
  std::vector<std::size_t> sweep;
  for (std::size_t t = 1; t < hardware; t *= 2)
    sweep.push_back(t);
  sweep.push_back(hardware);
  for (std::size_t t : sweep) {
    setThreads(t);
    Array<double> r;
    const double ms =
      medianMs(repeats, [&]() { r = model.potentials(molecule, points); });
    row("  sweep: " + std::to_string(t) + " thread" + (t > 1 ? "s" : ""), ms,
        false);
  }
  setThreads(0);

  if (extrapolated) {
    std::cout << "legacy timed on first " << legacyPoints << " of "
              << pointCount << " points and scaled (est.)\n";
  }
  std::cout << std::scientific << std::setprecision(3)
            << "max|legacy - default| over " << legacyPoints
            << " points: " << maxDiff
            << "   max|1 thread - default| over all points: " << maxDiffAll
            << "\n";
  return maxDiff == 0.0 && maxDiffAll == 0.0;
}

} // namespace

int main(int argc, char** argv)
{
  Options options;
  if (!parseArgs(argc, argv, options))
    return 1;

  const std::size_t hardware =
    std::max<std::size_t>(1, std::thread::hardware_concurrency());
  std::cout << "\nChargeModel::potentials() ESP benchmark\n"
            << "Data root: " << options.dataRoot
            << "\nHardware threads: " << hardware << "\n";

  bool ok = true;
  for (const auto& file : options.inputFiles) {
    const auto path = resolvePath(options.dataRoot, file);
    Molecule molecule;
    if (!std::filesystem::exists(path) ||
        !readMoleculeFromPath(path, molecule) || molecule.atomCount() == 0) {
      std::cout << "\n"
                << path.filename().string()
                << " error: unable to load molecule\n";
      ok = false;
      continue;
    }
    for (std::size_t count : options.pointCounts)
      ok = runWorkload(path.filename().string(), molecule, count, options,
                       hardware) &&
           ok;
  }
  return ok ? 0 : 2;
}
