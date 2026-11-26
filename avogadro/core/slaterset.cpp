/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "slaterset.h"

#include <algorithm>
#include <cmath>
#include <iostream>

#include <Eigen/LU>

namespace Avogadro::Core {

void SlaterSet::swapAtomIndices(Index a, Index b)
{
  const auto first = static_cast<int>(a);
  const auto second = static_cast<int>(b);
  for (auto& index : m_slaterIndices) {
    if (index == first)
      index = second;
    else if (index == second)
      index = first;
  }
}

bool SlaterSet::addSlaterIndices(const std::vector<int>& i)
{
  m_slaterIndices = i;
  return true;
}

bool SlaterSet::addSlaterTypes(const std::vector<int>& t)
{
  m_initialized = false;
  m_slaterTypes = t;
  return true;
}

bool SlaterSet::addZetas(const std::vector<double>& z)
{
  m_initialized = false;
  m_zetas = z;
  return true;
}

bool SlaterSet::addPQNs(const std::vector<int>& pqns)
{
  m_initialized = false;
  m_pqns = pqns;
  return true;
}

bool SlaterSet::addOverlapMatrix(const Eigen::MatrixXd& m)
{
  m_initialized = false;
  m_overlap.resize(m.rows(), m.cols());
  m_overlap = m;
  return true;
}

bool SlaterSet::addEigenVectors(const Eigen::MatrixXd& e)
{
  m_eigenVectors.resize(e.rows(), e.cols());
  m_eigenVectors = e;
  return true;
}

bool SlaterSet::addDensityMatrix(const Eigen::MatrixXd& d)
{
  m_density.resize(d.rows(), d.cols());
  m_density = d;
  return true;
}

unsigned int SlaterSet::molecularOrbitalCount(ElectronType) const
{
  return static_cast<unsigned int>(m_overlap.cols());
}

void SlaterSet::outputAll() {}

namespace {

// (2n)! as a double; 2n exceeds what an unsigned int holds for n >= 7.
// Returns 0 for a negative argument so the caller can reject it.
double factorialAsDouble(int n)
{
  if (n < 0)
    return 0.0;
  double result = 1.0;
  for (int i = 2; i <= n; ++i)
    result *= static_cast<double>(i);
  return result;
}

} // namespace

void SlaterSet::initCalculation()
{
  if (m_initialized)
    return;

  m_normalized.resize(0, 0);
  const Eigen::Index dim = m_overlap.rows();
  if (dim > 0 && m_overlap.cols() == dim && m_eigenVectors.rows() == dim) {
    Eigen::SelfAdjointEigenSolver<MatrixX> s(m_overlap);
    const MatrixX& p = s.eigenvectors();
    // S^(-1/2); a vanishing eigenvalue (linearly dependent basis) would
    // otherwise put an infinity in the matrix.
    Eigen::VectorXd invSqrt(dim);
    for (Eigen::Index i = 0; i < dim; ++i) {
      const double ev = s.eigenvalues()(i);
      invSqrt(i) = ev > 0.0 ? 1.0 / std::sqrt(ev) : 0.0;
    }
    MatrixX m = p * invSqrt.asDiagonal() * p.inverse();
    m_normalized = m * m_eigenVectors;

    if (!(m_overlap * m * m).eval().isIdentity())
      std::cout
        << "Identity test FAILED - do you need a newer version of Eigen?\n";
  }

  // The exponents stay in inverse bohr, as read from the file, and the basis
  // functions are evaluated with distances in bohr (see SlaterSetTools).
  // Converting them in place made a second initialization convert them again.
  //
  // Each STO is N r^(n-1) exp(-zeta r) Y_lm(x/r, y/r, z/r) with the real
  // solid harmonic Y_lm. The normalization N * (angular constant) goes into
  // m_factors. The angular polynomials in SlaterSetTools are not divided by
  // r^l (x instead of x/r for p, x^2 - y^2 instead of (x^2 - y^2)/r^2 for d),
  // so the remaining radial power is n - 1 - l, stored in m_PQNs.
  // A basis function with an invalid quantum number gets a zero factor.
  m_factors.assign(m_zetas.size(), 0.0);
  m_PQNs = m_pqns;
  const size_t count =
    std::min(m_zetas.size(), std::min(m_slaterTypes.size(), m_pqns.size()));
  m_PQNs.resize(m_zetas.size(), 0);
  for (size_t i = 0; i < count; ++i) {
    const int n = m_pqns[i];
    // (2n)! must be finite and nonzero, and n >= 1.
    if (n < 1 || n > 60 || !(m_zetas[i] > 0.0))
      continue;
    const double radial =
      std::pow(2.0 * m_zetas[i], n + 0.5) / std::sqrt(factorialAsDouble(2 * n));
    switch (m_slaterTypes[i]) {
      case S:
        m_factors[i] = radial * std::sqrt(1.0 / (4.0 * M_PI));
        m_PQNs[i] = n - 1;
        break;
      case PX:
      case PY:
      case PZ:
        m_factors[i] = radial * std::sqrt(3.0 / (4.0 * M_PI));
        m_PQNs[i] = n - 2;
        break;
      case X2:
        m_factors[i] = 0.5 * radial * std::sqrt(15.0 / (4.0 * M_PI));
        m_PQNs[i] = n - 3;
        break;
      case XZ:
      case YZ:
      case XY:
        m_factors[i] = radial * std::sqrt(15.0 / (4.0 * M_PI));
        m_PQNs[i] = n - 3;
        break;
      case Z2:
        m_factors[i] =
          (0.5 / std::sqrt(3.0)) * radial * std::sqrt(15.0 / (4.0 * M_PI));
        m_PQNs[i] = n - 3;
        break;
      default:
        std::cout << "Orbital " << i << " not handled, type "
                  << m_slaterTypes[i] << '\n';
    }
  }

  m_initialized = true;
}

} // End namespace Avogadro::Core
