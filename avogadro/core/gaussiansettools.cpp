/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gaussiansettools.h"

#include "cube.h"
#include "gaussianset.h"
#include "molecule.h"

#include <iostream>

using std::vector;

namespace Avogadro::Core {

GaussianSetTools::GaussianSetTools(Molecule* mol) : m_molecule(mol)
{
  if (m_molecule) {
    m_basis = dynamic_cast<GaussianSet*>(m_molecule->basisSet());
    m_cutoffDistances.resize(7, 0.0); // s, p, d, f, g, h, i (for now)
    calculateCutoffs();
  }
}

bool GaussianSetTools::calculateMolecularOrbital(Cube& cube, int moNumber) const
{
  for (size_t i = 0; i < cube.data()->size(); ++i) {
    Vector3 pos = cube.position(i);
    cube.setValue(i, calculateMolecularOrbital(pos, moNumber));
  }
  return true;
}

double GaussianSetTools::calculateMolecularOrbital(const Vector3& position,
                                                   int mo) const
{
  if (mo > static_cast<int>(m_basis->molecularOrbitalCount()))
    return 0.0;

  std::vector<double> values(calculateValues(position));

  const MatrixX& matrix = m_basis->moMatrix(m_type);
  int matrixSize(static_cast<int>(matrix.rows()));

  // Now calculate the value of the density at this point in space
  double result(0.0);
  for (int i = 0; i < matrixSize; ++i)
    result += matrix(i, mo) * values[i];

  return result;
}

bool GaussianSetTools::calculateElectronDensity(Cube& cube) const
{
  const MatrixX& matrix = m_basis->densityMatrix();
  if (matrix.rows() == 0 || matrix.cols() == 0) {
    // we don't have a density matrix, so generate one
    m_basis->generateDensityMatrix();
  }

  for (size_t i = 0; i < cube.data()->size(); ++i) {
    Vector3 pos = cube.position(i);
    cube.setValue(i, calculateElectronDensity(pos));
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

  std::vector<double> values(calculateValues(position));

  // Now calculate the value of the density at this point in space
  double rho(0.0);
  for (int i = 0; i < matrixSize; ++i) {
    // Calculate the off-diagonal parts of the matrix
    for (int j = 0; j < i; ++j)
      rho += 2.0 * matrix(i, j) * (values[i] * values[j]);
    // Now calculate the matrix diagonal
    rho += matrix(i, i) * (values[i] * values[i]);
  }

  return rho;
}

bool GaussianSetTools::calculateSpinDensity(Cube& cube) const
{
  for (size_t i = 0; i < cube.data()->size(); ++i) {
    Vector3 pos = cube.position(i);
    cube.setValue(i, calculateSpinDensity(pos));
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

  std::vector<double> values(calculateValues(position));

  // Now calculate the value of the density at this point in space
  double rho(0.0);
  for (int i = 0; i < matrixSize; ++i) {
    // Calculate the off-diagonal parts of the matrix
    for (int j = 0; j < i; ++j)
      rho += 2.0 * matrix(i, j) * (values[i] * values[j]);
    // Now calculate the matrix diagonal
    rho += matrix(i, i) * (values[i] * values[i]);
  }

  return rho;
}

bool GaussianSetTools::isValid() const
{
  return (m_molecule != nullptr) &&
         (dynamic_cast<GaussianSet*>(m_molecule->basisSet()) != nullptr);
}

inline bool GaussianSetTools::isSmall(double val) const
{
  return std::abs(val) < 1e-12;
}

inline void GaussianSetTools::calculateCutoffs()
{
  // Guesstimate a distance we can ignore the exp(-alpha * r^2) term
  // .. because it's negligible
  // This will depend on the angular momentum of the basis function
  // .. so we calculate it for whatever L values in this basis set

  const double threshold = 0.03 * 0.001; // 0.1% of a typical isovalue
  const double maxDistance = 100.0;      // just in case (diffuse functions)

  // get the exponents and normalized coefficients
  const std::vector<double>& exponents = m_basis->gtoA();
  const std::vector<double>& coefficients = m_basis->gtoCN();
  const std::vector<int>& sym = m_basis->symmetry();

  // we loop through the "symmetry" (i.e., L values in this basis set)
  for (size_t i = 0; i < sym.size(); ++i) {
    int L = symToL[sym[i]];

    // this is a hack, since not all coefficients will be the same
    // .. but it's a good approximation since they'll be similar
    unsigned int cIndex = m_basis->cIndices()[i];
    const double coeff = std::abs(coefficients[cIndex]);

    // now loop through all exponents for this L value
    // (e.g., multiple terms - we don't know which is the most diffuse)
    for (unsigned int j = m_basis->gtoIndices()[i];
         j < m_basis->gtoIndices()[i + 1]; ++j) {
      double alpha = exponents[j];
      // except for S, we don't want to start at the origin
      double r = std::min(maxDistance, std::sqrt(L / (2 * alpha)));
      double value = coeff * std::pow(r, L) * std::exp(-alpha * r * r);

      while (value > threshold && r < maxDistance) {
        r += 0.25;
        value = coeff * std::pow(r, L) * std::exp(-alpha * r * r);
      }

      m_cutoffDistances[L] = std::max(m_cutoffDistances[L], r * r);
    }
  }
}

inline std::vector<double> GaussianSetTools::calculateValues(
  const Vector3& position) const
{
  m_basis->initCalculation();
  Index atomsSize = m_molecule->atomCount();
  size_t basisSize = m_basis->symmetry().size();
  const std::vector<int>& basis = m_basis->symmetry();
  const std::vector<unsigned int>& atomIndices = m_basis->atomIndices();
  std::vector<Vector3> deltas;
  std::vector<double> dr2;
  deltas.reserve(atomsSize);
  dr2.reserve(atomsSize);

  // Calculate our position
  Vector3 pos(position * ANGSTROM_TO_BOHR);

  // Calculate the deltas for the position
  for (Index i = 0; i < atomsSize; ++i) {
    deltas.emplace_back(pos -
                        (m_molecule->atom(i).position3d() * ANGSTROM_TO_BOHR));
    dr2.push_back(deltas[i].squaredNorm());
  }

  // Allocate space for the values to be calculated.
  size_t matrixSize = m_basis->moMatrix().rows();
  std::vector<double> values;
  values.resize(matrixSize, 0.0);

  // Now calculate the values at this point in space
  for (unsigned int i = 0; i < basisSize; ++i) {
    // bail early if the distance is too big
    double cutoff = m_cutoffDistances[symToL[basis[i]]];
    if (dr2[atomIndices[i]] > cutoff)
      continue;

    switch (basis[i]) {
      case GaussianSet::S:
        pointS(i, dr2[atomIndices[i]], values);
        break;
      case GaussianSet::P:
        pointP(i, deltas[atomIndices[i]], dr2[atomIndices[i]], values);
        break;
      case GaussianSet::D:
        pointD(i, deltas[atomIndices[i]], dr2[atomIndices[i]], values);
        break;
      case GaussianSet::D5:
        pointD5(i, deltas[atomIndices[i]], dr2[atomIndices[i]], values);
        break;
      case GaussianSet::F:
        pointF(i, deltas[atomIndices[i]], dr2[atomIndices[i]], values);
        break;
      case GaussianSet::F7:
        pointF7(i, deltas[atomIndices[i]], dr2[atomIndices[i]], values);
        break;
      case GaussianSet::G:
        pointG(i, deltas[atomIndices[i]], dr2[atomIndices[i]], values);
        break;
      case GaussianSet::G9:
        pointG9(i, deltas[atomIndices[i]], dr2[atomIndices[i]], values);
        break;
      default:
        // Not handled - return a zero contribution
        ;
    }
  }

  return values;
}

inline void GaussianSetTools::pointS(unsigned int moIndex, double dr2,
                                     std::vector<double>& values) const
{
  // S type orbitals - the simplest of the calculations with one component
  double tmp = 0.0;
  unsigned int cIndex = m_basis->cIndices()[moIndex];
  for (unsigned int i = m_basis->gtoIndices()[moIndex];
       i < m_basis->gtoIndices()[moIndex + 1]; ++i) {
    tmp += m_basis->gtoCN()[cIndex++] * exp(-m_basis->gtoA()[i] * dr2);
  }
  // There is one MO coefficient per S shell basis.
  values[m_basis->moIndices()[moIndex]] = tmp;
}

inline void GaussianSetTools::pointP(unsigned int moIndex, const Vector3& delta,
                                     double dr2,
                                     std::vector<double>& values) const
{
  // P type orbitals have three components and each component has a different
  // independent MO weighting. Many things can be cached to save time though.
  unsigned int baseIndex = m_basis->moIndices()[moIndex];
  Vector3 components(Vector3::Zero());

  // Now iterate through the GTOs and sum their contributions
  unsigned int cIndex = m_basis->cIndices()[moIndex];
  double tmpGTO = 0.0;
  for (unsigned int i = m_basis->gtoIndices()[moIndex];
       i < m_basis->gtoIndices()[moIndex + 1]; ++i) {
    tmpGTO = exp(-m_basis->gtoA()[i] * dr2);
    for (unsigned int j = 0; j < 3; ++j) {
      components[j] += m_basis->gtoCN()[cIndex++] * tmpGTO;
    }
  }
  for (unsigned int i = 0; i < 3; ++i)
    values[baseIndex + i] = components[i] * delta[i];
}

inline void GaussianSetTools::pointD(unsigned int moIndex, const Vector3& delta,
                                     double dr2,
                                     std::vector<double>& values) const
{
  // D type orbitals have six components and each component has a different
  // independent MO weighting. Many things can be cached to save time though.
  unsigned int baseIndex = m_basis->moIndices()[moIndex];

  double components[6] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  const vector<double>& gtoA = m_basis->gtoA();
  const vector<double>& gtoCN = m_basis->gtoCN();

  // Now iterate through the GTOs and sum their contributions
  unsigned int cIndex = m_basis->cIndices()[moIndex];
  double tmpGTO = 0.0;
  for (unsigned int i = m_basis->gtoIndices()[moIndex];
       i < m_basis->gtoIndices()[moIndex + 1]; ++i) {
    // Calculate the common factor
    tmpGTO = exp(-gtoA[i] * dr2);
    for (double& component : components)
      component += gtoCN[cIndex++] * tmpGTO;
  }

  double componentsD[6] = { delta.x() * delta.x(),   // xx
                            delta.y() * delta.y(),   // yy
                            delta.z() * delta.z(),   // zz
                            delta.x() * delta.y(),   // xy
                            delta.x() * delta.z(),   // xz
                            delta.y() * delta.z() }; // yz

  for (int i = 0; i < 6; ++i)
    values[baseIndex + i] += components[i] * componentsD[i];
}

inline void GaussianSetTools::pointD5(unsigned int moIndex,
                                      const Vector3& delta, double dr2,
                                      std::vector<double>& values) const
{
  // D type orbitals have five components and each component has a different
  // MO weighting. Many things can be cached to save time.
  unsigned int baseIndex = m_basis->moIndices()[moIndex];
  double components[5] = { 0.0, 0.0, 0.0, 0.0, 0.0 };

  const vector<double>& gtoA = m_basis->gtoA();
  const vector<double>& gtoCN = m_basis->gtoCN();

  // Now iterate through the D type GTOs and sum their contributions
  unsigned int cIndex = m_basis->cIndices()[moIndex];
  double tmpGTO = 0.0;
  for (unsigned int i = m_basis->gtoIndices()[moIndex];
       i < m_basis->gtoIndices()[moIndex + 1]; ++i) {
    // Calculate the common factor
    tmpGTO = exp(-gtoA[i] * dr2);
    for (double& component : components)
      component += gtoCN[cIndex++] * tmpGTO;
  }

  // Calculate the prefactors
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
    values[baseIndex + i] += componentsD[i] * components[i];
}
inline void GaussianSetTools::pointF(unsigned int moIndex, const Vector3& delta,
                                     double dr2,
                                     std::vector<double>& values) const
{
  // F type orbitals have 10 components and each component has a different
  // independent MO weighting. Many things can be cached to save time though.
  unsigned int baseIndex = m_basis->moIndices()[moIndex];

  double components[10] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  const vector<double>& gtoA = m_basis->gtoA();
  const vector<double>& gtoCN = m_basis->gtoCN();

  // Now iterate through the GTOs and sum their contributions
  unsigned int cIndex = m_basis->cIndices()[moIndex];
  double tmpGTO = 0.0;
  for (unsigned int i = m_basis->gtoIndices()[moIndex];
       i < m_basis->gtoIndices()[moIndex + 1]; ++i) {
    // Calculate the common factor
    tmpGTO = exp(-gtoA[i] * dr2);
    for (double& component : components)
      component += gtoCN[cIndex++] * tmpGTO;
  }

  double xxx = delta.x() * delta.x() * delta.x(); // xxx
  double xxy = delta.x() * delta.x() * delta.y(); // xxy
  double xxz = delta.x() * delta.x() * delta.z(); // xxz
  double xyy = delta.x() * delta.y() * delta.y(); // xyy
  double xyz = delta.x() * delta.y() * delta.z(); // xyz
  double xzz = delta.x() * delta.z() * delta.z(); // xzz
  double yyy = delta.y() * delta.y() * delta.y(); // yyy
  double yyz = delta.y() * delta.y() * delta.z(); // yyz
  double yzz = delta.y() * delta.z() * delta.z(); // yzz
  double zzz = delta.z() * delta.z() * delta.z(); // zzz

  double componentsF[10] = {
    // molden order
    // e.g https://gau2grid.readthedocs.io/en/latest/order.html
    xxx, yyy, zzz, xyy, xxy, xxz, xzz, yzz, yyz, xyz
  };

  for (int i = 0; i < 10; ++i)
    values[baseIndex + i] += components[i] * componentsF[i];
}

inline void GaussianSetTools::pointF7(unsigned int moIndex,
                                      const Vector3& delta, double dr2,
                                      std::vector<double>& values) const
{
  // F type orbitals have 7 components and each component has a different
  // independent MO weighting. Many things can be cached to save time though.
  unsigned int baseIndex = m_basis->moIndices()[moIndex];

  double components[7] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  const vector<double>& gtoA = m_basis->gtoA();
  const vector<double>& gtoCN = m_basis->gtoCN();

  // Now iterate through the F type GTOs and sum their contributions
  unsigned int cIndex = m_basis->cIndices()[moIndex];
  double tmpGTO = 0.0;
  for (unsigned int i = m_basis->gtoIndices()[moIndex];
       i < m_basis->gtoIndices()[moIndex + 1]; ++i) {
    // Calculate the common factor
    tmpGTO = exp(-gtoA[i] * dr2);
    for (double& component : components)
      component += gtoCN[cIndex++] * tmpGTO;
  }

  double xxx = delta.x() * delta.x() * delta.x(); // xxx
  double xxy = delta.x() * delta.x() * delta.y(); // xxy
  double xxz = delta.x() * delta.x() * delta.z(); // xxz
  double xyy = delta.x() * delta.y() * delta.y(); // xyy
  double xyz = delta.x() * delta.y() * delta.z(); // xyz
  double xzz = delta.x() * delta.z() * delta.z(); // xzz
  double yyy = delta.y() * delta.y() * delta.y(); // yyy
  double yyz = delta.y() * delta.y() * delta.z(); // yyz
  double yzz = delta.y() * delta.z() * delta.z(); // yzz
  double zzz = delta.z() * delta.z() * delta.z(); // zzz

  /*
  spherical combinations borrowed from CASINO/Crystal documentation

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
    values[baseIndex + i] += components[i] * componentsF[i];
}

inline void GaussianSetTools::pointG(unsigned int moIndex, const Vector3& delta,
                                     double dr2, vector<double>& values) const
{
  // G type orbitals have 15 components and each component has a different
  // independent MO weighting. Many things can be cached to save time though.
  unsigned int baseIndex = m_basis->moIndices()[moIndex];

  double components[15] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  const vector<double>& gtoA = m_basis->gtoA();
  const vector<double>& gtoCN = m_basis->gtoCN();

  // Now iterate through the G type GTOs and sum their contributions
  unsigned int cIndex = m_basis->cIndices()[moIndex];
  double tmpGTO = 0.0;
  for (unsigned int i = m_basis->gtoIndices()[moIndex];
       i < m_basis->gtoIndices()[moIndex + 1]; ++i) {
    // Calculate the common factor
    tmpGTO = exp(-gtoA[i] * dr2);
    for (double& component : components)
      component += gtoCN[cIndex++] * tmpGTO;
  }

  // e.g. XXXX YYYY ZZZZ XXXY XXXZ XYYY YYYZ ZZZX ZZZY XXYY XXZZ YYZZ XXYZ XYYZ
  // XYZZ
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

  // molden order
  // https://www.theochem.ru.nl/molden/molden_format.html
  // https://gau2grid.readthedocs.io/en/latest/order.html
  // xxxx yyyy zzzz xxxy xxxz yyyx yyyz zzzx zzzy,
  // xxyy xxzz yyzz xxyz yyxz zzxy
  double componentsG[15] = { xxxx, yyyy, zzzz, xxxy, xxxz, yyyx, yyyz, zzzx,
                             zzzy, xxyy, xxzz, yyzz, xxyz, yyxz, zzxy };

  for (int i = 0; i < 15; ++i)
    values[baseIndex + i] += components[i] * componentsG[i];
}

inline void GaussianSetTools::pointG9(unsigned int moIndex,
                                      const Vector3& delta, double dr2,
                                      vector<double>& values) const
{
  // G type orbitals have 9 spherical components and each component
  // has a different independent MO weighting.
  // Many things can be cached to save time though.
  unsigned int baseIndex = m_basis->moIndices()[moIndex];

  double components[9] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  const vector<double>& gtoA = m_basis->gtoA();
  const vector<double>& gtoCN = m_basis->gtoCN();

  // Now iterate through the GTOs and sum their contributions
  unsigned int cIndex = m_basis->cIndices()[moIndex];
  double tmpGTO = 0.0;
  for (unsigned int i = m_basis->gtoIndices()[moIndex];
       i < m_basis->gtoIndices()[moIndex + 1]; ++i) {
    // Calculate the common factor
    tmpGTO = exp(-gtoA[i] * dr2);
    for (double& component : components)
      component += gtoCN[cIndex++] * tmpGTO;
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
    values[baseIndex + i] += components[i] * componentsG[i];
}

} // namespace Avogadro::Core
