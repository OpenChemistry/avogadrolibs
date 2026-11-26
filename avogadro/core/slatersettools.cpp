/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "slatersettools.h"

#include "avogadrocore.h"
#include "molecule.h"
#include "slaterset.h"

#include <cmath>
#include <utility>

namespace Avogadro::Core {

SlaterSetTools::SlaterSetTools(Molecule* mol) : m_molecule(mol)
{
  if (m_molecule)
    m_basis = dynamic_cast<SlaterSet*>(m_molecule->basisSet());
  // Initialize here, on the caller's thread: the concurrent calculators
  // evaluate points from many threads and must only read the basis set.
  if (m_basis != nullptr)
    m_basis->initCalculation();
}

double SlaterSetTools::calculateMolecularOrbital(const Vector3& position,
                                                 int mo) const
{
  if (m_molecule == nullptr || m_basis == nullptr || mo < 0)
    return 0.0;

  std::vector<double> values(calculateValues(position));

  // Orbitals are numbered from zero, the column of the coefficient matrix.
  const MatrixX& matrix = m_basis->normalizedMatrix();
  if (mo >= static_cast<int>(matrix.cols()) ||
      static_cast<size_t>(matrix.rows()) != values.size())
    return 0.0;

  // Now calculate the value of the orbital at this point in space
  double result(0.0);
  for (size_t i = 0; i < values.size(); ++i)
    result += matrix(static_cast<Eigen::Index>(i), mo) * values[i];

  return result;
}

double SlaterSetTools::calculateElectronDensity(const Vector3& position) const
{
  if (m_molecule == nullptr || m_basis == nullptr)
    return 0.0;

  std::vector<double> values(calculateValues(position));

  const MatrixX& matrix = m_basis->densityMatrix();
  const size_t matrixSize = values.size();
  if (static_cast<size_t>(matrix.rows()) != matrixSize ||
      static_cast<size_t>(matrix.cols()) != matrixSize ||
      static_cast<size_t>(m_basis->normalizedMatrix().rows()) != matrixSize)
    return 0.0;

  // Now calculate the value of the density at this point in space
  double rho(0.0);
  for (size_t i = 0; i < matrixSize; ++i) {
    const auto row = static_cast<Eigen::Index>(i);
    // Calculate the off-diagonal parts of the matrix
    for (size_t j = 0; j < i; ++j)
      rho += 2.0 * matrix(row, static_cast<Eigen::Index>(j)) *
             (values[i] * values[j]);
    // Now calculate the matrix diagonal
    rho += matrix(row, row) * (values[i] * values[i]);
  }

  return rho;
}

double SlaterSetTools::calculateSpinDensity(const Vector3&) const
{
  return 0.0;
}

bool SlaterSetTools::isValid() const
{
  // Only look: the mutable basisSet() would detach a shared basis set.
  return (m_molecule != nullptr) &&
         (dynamic_cast<const SlaterSet*>(
            std::as_const(*m_molecule).basisSet()) != nullptr);
}

inline bool SlaterSetTools::isSmall(double val) const
{
  return std::abs(val) < 1e-20;
}

std::vector<double> SlaterSetTools::calculateValues(
  const Vector3& position) const
{
  std::vector<double> values;
  if (m_molecule == nullptr || m_basis == nullptr)
    return values;

  m_basis->initCalculation();

  const Index atomsSize = m_molecule->atomCount();
  const std::vector<int>& slaterIndices = m_basis->slaterIndices();
  const std::vector<int>& slaterTypes = m_basis->slaterTypes();
  const std::vector<int>& PQNs = m_basis->PQNs();
  const std::vector<double>& factors = m_basis->factors();
  const std::vector<double>& zetas = m_basis->zetas();

  // All of the per-function arrays must describe the same functions.
  const size_t basisSize = zetas.size();
  if (slaterIndices.size() != basisSize || slaterTypes.size() != basisSize ||
      PQNs.size() != basisSize || factors.size() != basisSize)
    return values;

  // The exponents are in inverse bohr and the factors are normalized for
  // distances in bohr, so work in bohr; positions are stored in angstrom.
  std::vector<Vector3> deltas;
  std::vector<double> distances;
  deltas.reserve(atomsSize);
  distances.reserve(atomsSize);

  // Calculate the deltas for the position
  for (Index i = 0; i < atomsSize; ++i) {
    deltas.emplace_back((position - m_molecule->atom(i).position3d()) *
                        ANGSTROM_TO_BOHR_D);
    distances.push_back(deltas[i].norm());
  }

  // Allocate space for the values to be calculated.
  values.assign(basisSize, 0.0);

  // Now calculate the values at this point in space
  for (size_t i = 0; i < basisSize; ++i) {
    // A basis function on an atom that does not exist contributes nothing.
    if (slaterIndices[i] < 0 ||
        static_cast<Index>(slaterIndices[i]) >= atomsSize)
      continue;
    const double r = distances[slaterIndices[i]];
    const Vector3& delta = deltas[slaterIndices[i]];

    // N r^(n-1-l) exp(-zeta r) times the (unnormalized by r^l) angular
    // polynomial below; see SlaterSet::initCalculation().
    double value = factors[i] * std::exp(-zetas[i] * r);
    if (PQNs[i] >= 0) {
      for (int j = 0; j < PQNs[i]; ++j)
        value *= r;
    } else if (r > 0.0) {
      value *= std::pow(r, PQNs[i]);
    } else {
      continue; // not defined at the nucleus
    }
    switch (slaterTypes[i]) {
      case SlaterSet::S:
        break;
      case SlaterSet::PX:
        value *= delta.x();
        break;
      case SlaterSet::PY:
        value *= delta.y();
        break;
      case SlaterSet::PZ:
        value *= delta.z();
        break;
      case SlaterSet::X2: // (x^2 - y^2)r^n
        value *= delta.x() * delta.x() - delta.y() * delta.y();
        break;
      case SlaterSet::XZ: // xzr^n
        value *= delta.x() * delta.z();
        break;
      case SlaterSet::Z2: // (2z^2 - x^2 - y^2)r^n
        value *= 2.0 * delta.z() * delta.z() - delta.x() * delta.x() -
                 delta.y() * delta.y();
        break;
      case SlaterSet::YZ: // yzr^n
        value *= delta.y() * delta.z();
        break;
      case SlaterSet::XY: // xyr^n
        value *= delta.x() * delta.y();
        break;
      default:
        value = 0.0;
    }
    values[i] = value;
  }

  return values;
}

} // namespace Avogadro::Core
