/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").

  The model and algorithm are ported from grimme-lab/multicharge (v0.3.0,
  Apache-2.0, https://github.com/grimme-lab/multicharge).
******************************************************************************/

#include "eeqmodel.h"
#include "eeqdata.h"

#include <avogadro/core/molecule.h>

#include <Eigen/LU>

#include <cmath>
#include <cstddef>
#include <vector>

namespace Avogadro::Calc {

namespace {

// Bohr radius in Angstrom, CODATA 2018 (the value mctc-lib / multicharge use)
constexpr double BOHR_TO_ANGSTROM_EEQ = 0.529177210903;
constexpr double ANGSTROM_TO_BOHR_EEQ = 1.0 / BOHR_TO_ANGSTROM_EEQ;

constexpr double PI_EEQ = 3.141592653589793238462643;

// Error function counting steepness, pair cutoff (Bohr) and soft CN cap
constexpr double CN_STEEPNESS = 7.5;
constexpr double CN_CUTOFF = 25.0; // Bohr
constexpr double CN_MAX = 8.0;
// The D3-style covalent radii are the Pyykko-Atsumi radii scaled by 4/3
constexpr double COVALENT_SCALE = 4.0 / 3.0;
// Regularization of sqrt(CN) in the right-hand side
constexpr double CN_REGULARIZATION = 1.0e-14;
// Pairs closer than this (Bohr^2) do not count towards the CN
constexpr double CN_MIN_R2 = 1.0e-12;

inline bool supported(unsigned char atomicNumber)
{
  return atomicNumber >= 1 && atomicNumber <= EEQData::maxElement;
}

// Soft cap of the coordination number (multicharge log_cn_cut):
// log(1 + exp(cnMax)) - log(1 + exp(cnMax - cn)), evaluated without overflow.
inline double softCapCN(double cn, double cnMax)
{
  return std::log1p(std::exp(cnMax)) - std::log1p(std::exp(cnMax - cn));
}

// Erf-counting coordination numbers, positions in Bohr. Private so that a
// periodic version can extend it later.
std::vector<double> coordinationNumbers(const std::vector<Vector3>& xyz,
                                        const std::vector<double>& rcov)
{
  const std::size_t n = xyz.size();
  std::vector<double> cn(n, 0.0);
  const double cutoff2 = CN_CUTOFF * CN_CUTOFF;
  for (std::size_t i = 0; i < n; ++i) {
    for (std::size_t j = 0; j < i; ++j) {
      const double r2 = (xyz[i] - xyz[j]).squaredNorm();
      if (r2 > cutoff2 || r2 < CN_MIN_R2)
        continue;
      const double rc = rcov[i] + rcov[j];
      if (rc <= 0.0)
        continue;
      const double r = std::sqrt(r2);
      const double count =
        0.5 * (1.0 + std::erf(-CN_STEEPNESS * (r - rc) / rc));
      cn[i] += count;
      cn[j] += count;
    }
  }
  for (double& value : cn)
    value = softCapCN(value, CN_MAX);
  return cn;
}

} // namespace

Core::Molecule::ElementMask EEQModel::elements() const
{
  Core::Molecule::ElementMask mask;
  for (int z = 1; z <= EEQData::maxElement; ++z)
    mask.set(static_cast<std::size_t>(z));
  return mask;
}

MatrixX EEQModel::partialCharges(Core::Molecule& mol) const
{
  return partialCharges(static_cast<const Core::Molecule&>(mol));
}

MatrixX EEQModel::partialCharges(const Core::Molecule& mol) const
{
  const std::size_t atomCount = mol.atomCount();
  const auto count = static_cast<Eigen::Index>(atomCount);
  MatrixX charges = MatrixX::Zero(count, 1);
  if (atomCount == 0)
    return charges;

  if (atomCount > maxAtoms()) {
    appendError("EEQ charges are limited to " + std::to_string(maxAtoms()) +
                " atoms; this molecule has " + std::to_string(atomCount) + ".");
    return charges;
  }

  const Core::Array<unsigned char>& numbers = mol.atomicNumbers();
  const Core::Array<Vector3>& positions = mol.atomPositions3d();
  if (numbers.size() != atomCount || positions.size() != atomCount) {
    appendError("EEQ: inconsistent atom data.");
    return charges;
  }

  std::vector<Vector3> xyz(atomCount);
  std::vector<double> rcov(atomCount);
  for (std::size_t i = 0; i < atomCount; ++i) {
    if (!supported(numbers[i])) {
      appendError("EEQ charges are only parameterized for elements 1-103.");
      return charges;
    }
    xyz[i] = positions[i] * ANGSTROM_TO_BOHR_EEQ;
    rcov[i] = COVALENT_SCALE * EEQData::covalentRadius[numbers[i]] *
              ANGSTROM_TO_BOHR_EEQ;
  }

  const std::vector<double> cn = coordinationNumbers(xyz, rcov);

  // Bordered system A (q, lambda) = x
  const double sqrt2OverPi = std::sqrt(2.0 / PI_EEQ);
  const double twoOverSqrtPi = 2.0 / std::sqrt(PI_EEQ);
  MatrixX a = MatrixX::Zero(count + 1, count + 1);
  Eigen::VectorXd x = Eigen::VectorXd::Zero(count + 1);
  for (std::size_t i = 0; i < atomCount; ++i) {
    const unsigned char zi = numbers[i];
    const double radI = EEQData::rad[zi];
    const auto ii = static_cast<Eigen::Index>(i);
    for (std::size_t j = 0; j < i; ++j) {
      const double radJ = EEQData::rad[numbers[j]];
      const double sigma = std::sqrt(radI * radI + radJ * radJ);
      const double r = (xyz[i] - xyz[j]).norm();
      double value;
      if (r < 1.0e-8) // coincident atoms: limit of erf(r / sigma) / r
        value = twoOverSqrtPi / sigma;
      else
        value = std::erf(r / sigma) / r;
      a(ii, static_cast<Eigen::Index>(j)) = value;
      a(static_cast<Eigen::Index>(j), ii) = value;
    }
    a(ii, ii) = EEQData::eta[zi] + sqrt2OverPi / radI;
    x(ii) = -EEQData::chi[zi] +
            EEQData::kcnchi[zi] / std::sqrt(cn[i] + CN_REGULARIZATION) * cn[i];
    a(ii, count) = 1.0;
    a(count, ii) = 1.0;
  }
  x(count) = static_cast<double>(mol.totalCharge());

  // Solve in place to avoid a second N x N copy
  Eigen::PartialPivLU<Eigen::Ref<MatrixX>> lu(a);
  const Eigen::VectorXd solution = lu.solve(x);
  if (!solution.allFinite()) {
    appendError("EEQ: the charge equations could not be solved.");
    return charges;
  }

  charges = solution.head(count);
  return charges;
}

} // namespace Avogadro::Calc
