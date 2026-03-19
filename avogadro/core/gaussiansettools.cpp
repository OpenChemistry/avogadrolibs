/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gaussiansettools.h"

#include "cube.h"
#include "gaussianset.h"
#include "molecule.h"

#include <iostream>

namespace Avogadro::Core {

GaussianSetTools::GaussianSetTools(Molecule* mol) : m_molecule(mol)
{
  if (m_molecule) {
    m_basis = dynamic_cast<GaussianSet*>(m_molecule->basisSet());

    // Pre-compute atom positions in Bohr as 3 x N matrix for vectorized ops
    Index atomsSize = m_molecule->atomCount();
    m_atomPositionsBohr.resize(3, atomsSize);
    for (Index i = 0; i < atomsSize; ++i) {
      m_atomPositionsBohr.col(i) =
        m_molecule->atom(i).position3d() * ANGSTROM_TO_BOHR;
    }

    // Initialize the basis set calculation once (normalizes coefficients, etc.)
    // Then build pre-packed shell data for fast evaluation
    if (m_basis) {
      m_basis->initCalculation();
      buildShellData();
    }
  }
}

void GaussianSetTools::buildShellData()
{
  const std::vector<int>& sym = m_basis->symmetry();
  const std::vector<unsigned int>& atomIndices = m_basis->atomIndices();
  const std::vector<unsigned int>& moIndices = m_basis->moIndices();
  const std::vector<unsigned int>& gtoIndices = m_basis->gtoIndices();
  const std::vector<unsigned int>& cIndices = m_basis->cIndices();

  // Take local contiguous copies of exponents and normalized coefficients
  m_gtoA = m_basis->gtoA();
  m_gtoCN = m_basis->gtoCN();

  m_shells.resize(sym.size());
  for (size_t i = 0; i < sym.size(); ++i) {
    ShellInfo& s = m_shells[i];
    s.type = sym[i];
    s.L = symToL[sym[i]];
    s.atomIndex = atomIndices[i];
    s.moIndex = moIndices[i];
    s.gtoStart = gtoIndices[i];
    s.gtoEnd = gtoIndices[i + 1];
    s.cStart = cIndices[i];
    s.nComponents = symToNComp[sym[i]];

    // Cache center in Bohr
    s.centerBohr[0] = m_atomPositionsBohr(0, s.atomIndex);
    s.centerBohr[1] = m_atomPositionsBohr(1, s.atomIndex);
    s.centerBohr[2] = m_atomPositionsBohr(2, s.atomIndex);

    // Calculate per-shell cutoff
    s.cutoffSquared = calculateShellCutoff(s);
  }
}

double GaussianSetTools::calculateShellCutoff(const ShellInfo& shell) const
{
  const double threshold = 0.03 * 0.001; // 0.1% of a typical isovalue
  const double maxDistance = 100.0;

  double maxR2 = 0.0;
  const double coeff = std::abs(m_gtoCN[shell.cStart]);

  for (unsigned int j = shell.gtoStart; j < shell.gtoEnd; ++j) {
    double alpha = m_gtoA[j];
    // Start at the peak of r^L * exp(-alpha * r^2) for L > 0
    double r = std::min(maxDistance, std::sqrt(shell.L / (2.0 * alpha)));
    double value = coeff * std::pow(r, shell.L) * std::exp(-alpha * r * r);

    while (value > threshold && r < maxDistance) {
      r += 0.25;
      value = coeff * std::pow(r, shell.L) * std::exp(-alpha * r * r);
    }

    maxR2 = std::max(maxR2, r * r);
  }

  return maxR2;
}

bool GaussianSetTools::calculateMolecularOrbital(Cube& cube, int moNumber) const
{
  if (moNumber > static_cast<int>(m_basis->molecularOrbitalCount()))
    return false;

  const MatrixX& matrix = m_basis->moMatrix(m_type);
  const auto& moCol = matrix.col(moNumber);
  Eigen::VectorXd values;

  for (size_t i = 0; i < cube.data()->size(); ++i) {
    Vector3 pos = cube.position(i);
    calculateValues(pos, values);
    cube.setValue(i, moCol.dot(values));
  }
  return true;
}

double GaussianSetTools::calculateMolecularOrbital(const Vector3& position,
                                                   int mo) const
{
  if (mo > static_cast<int>(m_basis->molecularOrbitalCount()))
    return 0.0;

  Eigen::VectorXd values;
  calculateValues(position, values);

  const MatrixX& matrix = m_basis->moMatrix(m_type);

  // Use Eigen's optimized dot product
  return matrix.col(mo).dot(values);
}

bool GaussianSetTools::calculateElectronDensity(Cube& cube) const
{
  const MatrixX& matrix = m_basis->densityMatrix();
  if (matrix.rows() == 0 || matrix.cols() == 0) {
    // we don't have a density matrix, so generate one
    m_basis->generateDensityMatrix();
  }

  int matrixSize = static_cast<int>(m_basis->moMatrix().rows());
  if (matrix.rows() != matrixSize || matrix.cols() != matrixSize)
    return false;

  Eigen::VectorXd values;
  Eigen::VectorXd tmp;

  for (size_t i = 0; i < cube.data()->size(); ++i) {
    Vector3 pos = cube.position(i);
    calculateValues(pos, values);
    tmp.noalias() = matrix * values;
    cube.setValue(i, values.dot(tmp));
  }
  return true;
}

double GaussianSetTools::calculateElectronDensity(const Vector3& position) const
{
  const MatrixX& matrix = m_basis->densityMatrix();
  int matrixSize(static_cast<int>(m_basis->moMatrix().rows()));

  if (matrix.rows() != matrixSize || matrix.cols() != matrixSize) {
    return 0.0;
  }

  Eigen::VectorXd values;
  calculateValues(position, values);

  // Compute the quadratic form: v^T * D * v
  // The density matrix is symmetric, so we can use the full matrix multiply
  return values.dot(matrix * values);
}

bool GaussianSetTools::calculateSpinDensity(Cube& cube) const
{
  const MatrixX& matrix = m_basis->spinDensityMatrix();
  int matrixSize = static_cast<int>(m_basis->moMatrix().rows());
  if (matrix.rows() != matrixSize || matrix.cols() != matrixSize)
    return false;

  Eigen::VectorXd values;
  Eigen::VectorXd tmp;

  for (size_t i = 0; i < cube.data()->size(); ++i) {
    Vector3 pos = cube.position(i);
    calculateValues(pos, values);
    tmp.noalias() = matrix * values;
    cube.setValue(i, values.dot(tmp));
  }
  return true;
}

double GaussianSetTools::calculateSpinDensity(const Vector3& position) const
{
  const MatrixX& matrix = m_basis->spinDensityMatrix();
  int matrixSize(static_cast<int>(m_basis->moMatrix().rows()));
  if (matrix.rows() != matrixSize || matrix.cols() != matrixSize) {
    return 0.0;
  }

  Eigen::VectorXd values;
  calculateValues(position, values);

  // Compute the quadratic form: v^T * D * v
  // The spin density matrix is symmetric, so we can use the full matrix
  // multiply
  return values.dot(matrix * values);
}

bool GaussianSetTools::isValid() const
{
  return (m_molecule != nullptr) &&
         (dynamic_cast<GaussianSet*>(m_molecule->basisSet()) != nullptr);
}

inline void GaussianSetTools::calculateValues(const Vector3& position,
                                              Eigen::VectorXd& values) const
{
  // Calculate our position in Bohr
  Vector3 pos(position * ANGSTROM_TO_BOHR);

  // Resize and zero the output vector
  Index matrixSize = m_basis->moMatrix().rows();
  values.setZero(matrixSize);

  // Loop over pre-packed shells, computing delta per-shell from cached centers
  for (const auto& shell : m_shells) {
    Vector3 delta(pos.x() - shell.centerBohr[0], pos.y() - shell.centerBohr[1],
                  pos.z() - shell.centerBohr[2]);
    double dr2_i = delta.squaredNorm();

    // Bail early if the distance to this shell's center is beyond cutoff
    if (dr2_i > shell.cutoffSquared)
      continue;

    switch (shell.type) {
      case GaussianSet::S:
        pointS(shell, dr2_i, values);
        break;
      case GaussianSet::P:
        pointP(shell, delta, dr2_i, values);
        break;
      case GaussianSet::D:
        pointD(shell, delta, dr2_i, values);
        break;
      case GaussianSet::D5:
        pointD5(shell, delta, dr2_i, values);
        break;
      case GaussianSet::F:
        pointF(shell, delta, dr2_i, values);
        break;
      case GaussianSet::F7:
        pointF7(shell, delta, dr2_i, values);
        break;
      case GaussianSet::G:
        pointG(shell, delta, dr2_i, values);
        break;
      case GaussianSet::G9:
        pointG9(shell, delta, dr2_i, values);
        break;
      default:
        // Not handled - return a zero contribution
        ;
    }
  }
}

inline void GaussianSetTools::pointS(const ShellInfo& shell, double dr2,
                                     Eigen::VectorXd& values) const
{
  // S type orbitals - one component
  double tmp = 0.0;
  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    tmp += m_gtoCN[cIndex++] * exp(-m_gtoA[i] * dr2);
  }
  values[shell.moIndex] = tmp;
}

inline void GaussianSetTools::pointP(const ShellInfo& shell,
                                     const Vector3& delta, double dr2,
                                     Eigen::VectorXd& values) const
{
  // P type orbitals have three components
  Vector3 components(Vector3::Zero());

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (unsigned int j = 0; j < 3; ++j) {
      components[j] += m_gtoCN[cIndex++] * tmpGTO;
    }
  }
  for (unsigned int i = 0; i < 3; ++i)
    values[shell.moIndex + i] = components[i] * delta[i];
}

inline void GaussianSetTools::pointD(const ShellInfo& shell,
                                     const Vector3& delta, double dr2,
                                     Eigen::VectorXd& values) const
{
  // D type orbitals have six cartesian components
  double components[6] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (double& component : components)
      component += m_gtoCN[cIndex++] * tmpGTO;
  }

  double componentsD[6] = { delta.x() * delta.x(),   // xx
                            delta.y() * delta.y(),   // yy
                            delta.z() * delta.z(),   // zz
                            delta.x() * delta.y(),   // xy
                            delta.x() * delta.z(),   // xz
                            delta.y() * delta.z() }; // yz

  for (int i = 0; i < 6; ++i)
    values[shell.moIndex + i] += components[i] * componentsD[i];
}

inline void GaussianSetTools::pointD5(const ShellInfo& shell,
                                      const Vector3& delta, double dr2,
                                      Eigen::VectorXd& values) const
{
  // D type orbitals have five spherical components
  double components[5] = { 0.0, 0.0, 0.0, 0.0, 0.0 };

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (double& component : components)
      component += m_gtoCN[cIndex++] * tmpGTO;
  }

  double xx = delta.x() * delta.x();
  double yy = delta.y() * delta.y();
  double zz = delta.z() * delta.z();
  double xy = delta.x() * delta.y();
  double xz = delta.x() * delta.z();
  double yz = delta.y() * delta.z();

  double componentsD[5] = { zz - dr2, // 0
                            xz,       // 1p
                            yz,       // 1n
                            xx - yy,  // 2p
                            xy };     // 2n

  for (int i = 0; i < 5; ++i)
    values[shell.moIndex + i] += componentsD[i] * components[i];
}

inline void GaussianSetTools::pointF(const ShellInfo& shell,
                                     const Vector3& delta, double dr2,
                                     Eigen::VectorXd& values) const
{
  // F type orbitals have 10 cartesian components
  double components[10] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (double& component : components)
      component += m_gtoCN[cIndex++] * tmpGTO;
  }

  double xxx = delta.x() * delta.x() * delta.x();
  double xxy = delta.x() * delta.x() * delta.y();
  double xxz = delta.x() * delta.x() * delta.z();
  double xyy = delta.x() * delta.y() * delta.y();
  double xyz = delta.x() * delta.y() * delta.z();
  double xzz = delta.x() * delta.z() * delta.z();
  double yyy = delta.y() * delta.y() * delta.y();
  double yyz = delta.y() * delta.y() * delta.z();
  double yzz = delta.y() * delta.z() * delta.z();
  double zzz = delta.z() * delta.z() * delta.z();

  // Molden order
  double componentsF[10] = { xxx, yyy, zzz, xyy, xxy, xxz, xzz, yzz, yyz, xyz };

  for (int i = 0; i < 10; ++i)
    values[shell.moIndex + i] += components[i] * componentsF[i];
}

inline void GaussianSetTools::pointF7(const ShellInfo& shell,
                                      const Vector3& delta, double dr2,
                                      Eigen::VectorXd& values) const
{
  // F type orbitals have 7 spherical components
  double components[7] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (double& component : components)
      component += m_gtoCN[cIndex++] * tmpGTO;
  }

  double xxx = delta.x() * delta.x() * delta.x();
  double xxy = delta.x() * delta.x() * delta.y();
  double xxz = delta.x() * delta.x() * delta.z();
  double xyy = delta.x() * delta.y() * delta.y();
  double xyz = delta.x() * delta.y() * delta.z();
  double xzz = delta.x() * delta.z() * delta.z();
  double yyy = delta.y() * delta.y() * delta.y();
  double yyz = delta.y() * delta.y() * delta.z();
  double yzz = delta.y() * delta.z() * delta.z();
  double zzz = delta.z() * delta.z() * delta.z();

  /*
  Spherical combinations borrowed from CASINO/Crystal documentation

   linear combination
3,0     z^3 - 3/2 * (x^2z + y^2z)      2z^3 - 3 * (x^2z + y^2z)      * 2
3,1     6 * xz^2 - 3/2 * (x^3 + xy^2)  4xz^2 - x^3 - xy^2            * 2/3
3,-1    6 * yz^2 - 3/2 * (x^2y + y^3)  4yz^2 - x^2y - y^3            * 2/3
3,2     15 * (x^2z - y^2z)             x^2z - y^2z                   * 1/15
3,-2    30 * xyz                       xyz                           * 1/30
3,3     15 * x^3 - 45 * xy^2           x^3 - 3xy^2                   * 1/15
3,-3    45 * x^2y - 15 * y^3           3x^2y - y^3                   * 1/15

final normalization
          (2 - delta_m,0) * (l - |m|)!
*  root  ------------------------------                     (m-dependent)
                (l + m)!
*/
  double root6 = 2.449489742783178;
  double root60 = 7.745966692414834;
  double root360 = 18.973665961010276;
  double componentsF[7] = { zzz - 3.0 / 2.0 * (xxz + yyz),
                            (6.0 * xzz - 3.0 / 2.0 * (xxx + xyy)) / root6,
                            (6.0 * yzz - 3.0 / 2.0 * (xxy + yyy)) / root6,
                            (15.0 * (xxz - yyz)) / root60,
                            (30.0 * xyz) / root60,
                            (15.0 * xxx - 45.0 * xyy) / root360,
                            (45.0 * xxy - 15.0 * yyy) / root360 };

  for (int i = 0; i < 7; ++i)
    values[shell.moIndex + i] += components[i] * componentsF[i];
}

inline void GaussianSetTools::pointG(const ShellInfo& shell,
                                     const Vector3& delta, double dr2,
                                     Eigen::VectorXd& values) const
{
  // G type orbitals have 15 cartesian components
  double components[15] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (double& component : components)
      component += m_gtoCN[cIndex++] * tmpGTO;
  }

  const double xxxx = delta.x() * delta.x() * delta.x() * delta.x();
  const double yyyy = delta.y() * delta.y() * delta.y() * delta.y();
  const double zzzz = delta.z() * delta.z() * delta.z() * delta.z();
  const double xxxy = delta.x() * delta.x() * delta.x() * delta.y();
  const double xxxz = delta.x() * delta.x() * delta.x() * delta.z();
  const double yyyx = delta.y() * delta.y() * delta.y() * delta.x();
  const double yyyz = delta.y() * delta.y() * delta.y() * delta.z();
  const double zzzx = delta.z() * delta.z() * delta.z() * delta.x();
  const double zzzy = delta.z() * delta.z() * delta.z() * delta.y();
  const double xxyy = delta.x() * delta.x() * delta.y() * delta.y();
  const double xxzz = delta.x() * delta.x() * delta.z() * delta.z();
  const double yyzz = delta.y() * delta.y() * delta.z() * delta.z();
  const double xxyz = delta.x() * delta.x() * delta.y() * delta.z();
  const double yyxz = delta.y() * delta.y() * delta.x() * delta.z();
  const double zzxy = delta.z() * delta.z() * delta.x() * delta.y();

  // Molden order
  double componentsG[15] = { xxxx, yyyy, zzzz, xxxy, xxxz, yyyx, yyyz, zzzx,
                             zzzy, xxyy, xxzz, yyzz, xxyz, yyxz, zzxy };

  for (int i = 0; i < 15; ++i)
    values[shell.moIndex + i] += components[i] * componentsG[i];
}

inline void GaussianSetTools::pointG9(const ShellInfo& shell,
                                      const Vector3& delta, double dr2,
                                      Eigen::VectorXd& values) const
{
  // G type orbitals have 9 spherical components
  double components[9] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  unsigned int cIndex = shell.cStart;
  for (unsigned int i = shell.gtoStart; i < shell.gtoEnd; ++i) {
    double tmpGTO = exp(-m_gtoA[i] * dr2);
    for (double& component : components)
      component += m_gtoCN[cIndex++] * tmpGTO;
  }

  double x2(delta.x() * delta.x()), y2(delta.y() * delta.y()),
    z2(delta.z() * delta.z());

  double componentsG[9] = {
    3.0 * dr2 * dr2 - 30.0 * dr2 * z2 + 35.0 * z2 * z2 * (1.0 / 8.0),
    delta.x() * delta.z() * (7.0 * z2 - 3.0 * dr2) * (sqrt(5.0) / 8.0),
    delta.y() * delta.z() * (7.0 * z2 - 3.0 * dr2) * (sqrt(5.0) / 8.0),
    (x2 - y2) * (7.0 * z2 - dr2) * (sqrt(5.0) / 4.0),
    delta.x() * delta.y() * (7.0 * z2 - dr2) * (sqrt(5.0) / 2.0),
    delta.x() * delta.z() * (x2 - 3.0 * y2) * (sqrt(7.0) / 4.0),
    delta.y() * delta.z() * (3.0 * x2 - y2) * (sqrt(7.0) / 4.0),
    (x2 * x2 - 6.0 * x2 * y2 + y2 * y2) * (sqrt(35.0) / 8.0),
    delta.x() * delta.y() * (x2 - y2) * (sqrt(35.0) / 2.0)
  };

  for (int i = 0; i < 9; ++i)
    values[shell.moIndex + i] += components[i] * componentsG[i];
}

} // namespace Avogadro::Core
