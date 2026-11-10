/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "chargemodel.h"

#include <Eigen/src/Core/util/Meta.h>
#include <avogadro/core/array.h>
#include <avogadro/core/molecule.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <system_error>
#include <thread>
#include <vector>
#include <functional>

namespace Avogadro {

using Core::Array;
using Core::Molecule;

namespace Calc {

#ifndef M_PI
constexpr double M_PI = 3.14159265358979323846;
#endif

Vector3 ChargeModel::dipoleMoment(const Molecule& mol) const
{
  if (mol.atomCount() < 2)
    return Vector3(0.0, 0.0, 0.0);

  // default is to get the set of partial atomic charges
  // (some models might do something more sophisticated)
  const MatrixX charges = partialCharges(mol);
  // also get the positions of the atoms
  const Array<Vector3>& positions = mol.atomPositions3d();

  Vector3 dipole(0.0, 0.0, 0.0);
  if (charges.cols() < 1 ||
      static_cast<std::size_t>(charges.rows()) != positions.size())
    std::cout << "Error: charges " << charges.rows() << "x" << charges.cols()
              << " does not match " << positions.size() << " positions" << '\n';

  const Eigen::Index count =
    std::min(charges.rows(), static_cast<Eigen::Index>(positions.size()));
  for (Eigen::Index i = 0; i < count && charges.cols() > 0; ++i)
    dipole += charges(i, 0) * positions[i];

  dipole *= 4.80320471257; // convert to Debye from electron-Angstrom

  return dipole;
}

namespace {

// Point-charge kernel shared by potential() and potentials() so both give
// bit-identical results. Sums q[i] / |r[i] - point| over the atoms in order,
// dropping very small distances to avoid overflow. The caller applies the
// dielectric constant.
inline double pointChargeSum(const double* q, const Vector3* r,
                             std::size_t count, const Vector3& point)
{
  double sum = 0.0;
  for (std::size_t i = 0; i < count; ++i) {
    const double distance = (r[i] - point).norm();
    if (distance > 0.01)
      sum += q[i] / distance;
  }
  return sum;
}

// Evaluate points [begin, end) into out. Each call touches only its own
// slice of out; q, r and points are read-only, so no locking is needed.
void evaluateRange(const std::vector<double>& q, const std::vector<Vector3>& r,
                   const Array<Vector3>& points, double dielectric,
                   std::size_t begin, std::size_t end, double* out)
{
  for (std::size_t i = begin; i < end; ++i)
    out[i] =
      pointChargeSum(q.data(), r.data(), q.size(), points[i]) / dielectric;
}

// A non-positive or non-finite dielectric constant is meaningless (and would
// divide by zero); treat it as vacuum.
inline double effectiveDielectric(double dielectric)
{
  return (dielectric > 0.0 && std::isfinite(dielectric)) ? dielectric : 1.0;
}

// Minimum number of (point, atom) pair evaluations per thread. Each pair costs
// a few ns (sqrt + divide), so this is roughly 0.2-0.5 ms of work, which is
// well above the ~50 microsecond cost of starting a thread. Smaller jobs run
// on the calling thread.
constexpr std::size_t MinPairsPerThread = 100000;

// Optional override of the thread count for potentials(), used by the ESP
// benchmark (and handy for debugging / limiting CPU use). Returns 0 when
// AVOGADRO_ESP_THREADS is unset or invalid. Kept as an environment variable
// so it adds nothing to the public API.
std::size_t threadCountOverride()
{
  const char* value = std::getenv("AVOGADRO_ESP_THREADS");
  if (value == nullptr || *value == '\0')
    return 0;
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(value, &end, 10);
  if (end == value || *end != '\0')
    return 0;
  return static_cast<std::size_t>(parsed);
}

} // namespace

double ChargeModel::potential(Molecule& mol, const Vector3& point) const
{
  // default is to get the set of partial atomic charges
  const MatrixX charges = partialCharges(mol);
  // also get the positions of the atoms
  const Array<Vector3>& positions = mol.atomPositions3d();

  // @todo: this is naive and inefficient
  //  calculate the atoms within a cutoff distance
  //  and sum the potentials
  if (charges.cols() < 1)
    return 0.0;

  const std::size_t count =
    std::min(static_cast<std::size_t>(charges.rows()), positions.size());
  // charges is column-major, so column 0 is contiguous
  const double sum =
    pointChargeSum(charges.data(), positions.data(), count, point);
  return sum / effectiveDielectric(m_dielectric);
}

Array<double> ChargeModel::potentials(Core::Molecule& mol,
                                      const Array<Vector3>& points) const
{
  Array<double> results(points.size(), 0.0);
  if (points.empty())
    return results;

  // Fetch the charges and positions once, not once per point
  const MatrixX charges = partialCharges(mol);
  const Array<Vector3>& positions = mol.atomPositions3d();
  if (charges.cols() < 1)
    return results;

  const std::size_t count =
    std::min(static_cast<std::size_t>(charges.rows()), positions.size());
  if (count == 0)
    return results;

  // contiguous copies, shared read-only by all threads
  std::vector<double> q(charges.data(), charges.data() + count);
  std::vector<Vector3> r(positions.data(), positions.data() + count);

  const std::size_t n = points.size();
  const double dielectric = effectiveDielectric(m_dielectric);
  double* out = results.data();

  std::size_t threadCount = 1;
#if !(defined(__EMSCRIPTEN__) && !defined(__EMSCRIPTEN_PTHREADS__))
  const std::size_t hardware =
    std::max<std::size_t>(1, std::thread::hardware_concurrency());
  // cap so each thread gets at least MinPairsPerThread pair evaluations
  const std::size_t byWork =
    std::max<std::size_t>(1, (n * count) / MinPairsPerThread);
  threadCount = std::min({ hardware, byWork, n });
  // an explicit override bypasses the work heuristic (but never exceeds n)
  const std::size_t forced = threadCountOverride();
  if (forced > 0)
    threadCount = std::min(forced, n);
#endif

  if (threadCount <= 1) {
    evaluateRange(q, r, points, dielectric, 0, n, out);
    return results;
  }

#if !(defined(__EMSCRIPTEN__) && !defined(__EMSCRIPTEN_PTHREADS__))
  // contiguous, disjoint chunks of the output
  const std::size_t chunk = (n + threadCount - 1) / threadCount;
  std::vector<std::thread> threads;
  threads.reserve(threadCount);
  std::size_t begin = 0;
  // the last chunk is always computed on the calling thread
  while (begin < n) {
    const std::size_t end = std::min(n, begin + chunk);
    if (end == n)
      break;
    try {
      threads.emplace_back(evaluateRange, std::cref(q), std::cref(r),
                           std::cref(points), dielectric, begin, end, out);
    } catch (const std::system_error&) {
      // could not start a thread: compute this chunk here instead
      evaluateRange(q, r, points, dielectric, begin, end, out);
    }
    begin = end;
  }
  evaluateRange(q, r, points, dielectric, begin, n, out);
  for (auto& t : threads)
    t.join();
#endif

  return results;
}

void ChargeModel::appendError(const std::string& errorString,
                              bool newLine) const
{
  m_error += errorString;
  if (newLine)
    m_error += "\n";
}

} // namespace Calc
} // namespace Avogadro
