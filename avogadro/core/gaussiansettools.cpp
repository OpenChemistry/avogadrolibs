/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2008-2009 Marcus D. Hanwell
  Copyright 2008 Albert De Fusco
  Copyright 2010-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "gaussiansettools.h"

#include "gaussianset.h"
#include "molecule.h"

#include <iostream>

using std::cout;
using std::endl;

using std::vector;

namespace Avogadro {
namespace Core {

GaussianSetTools::GaussianSetTools(Molecule *mol) : m_molecule(mol)
{
  if (m_molecule)
    m_basis = dynamic_cast<GaussianSet *>(m_molecule->basisSet());
}

GaussianSetTools::~GaussianSetTools()
{
}

double GaussianSetTools::calculateMolecularOrbital(const Vector3 &position,
                                                   int mo) const
{
  if (mo > static_cast<int>(m_basis->molecularOrbitalCount()))
    return 0.0;

  vector<double> values(calculateValues(position));

  const MatrixX &matrix = m_basis->moMatrix();
  int matrixSize(matrix.rows());
  int indexMO(mo - 1);

  // Now calculate the value of the density at this point in space
  double result(0.0);
  for (int i = 0; i < matrixSize; ++i)
    result += matrix(i, indexMO) * values[i];

  return result;
}

double GaussianSetTools::calculateElectronDensity(const Vector3 &position) const
{
  const MatrixX &matrix = m_basis->densityMatrix();
  int matrixSize(m_basis->moMatrix().rows());
  if (matrix.rows() != matrixSize || matrix.cols() != matrixSize) {
    return 0.0;
  }

  vector<double> values(calculateValues(position));

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

double GaussianSetTools::calculateSpinDensity(const Vector3 &position) const
{
  const MatrixX &matrix = m_basis->spinDensityMatrix();
  int matrixSize(m_basis->moMatrix().rows());
  if (matrix.rows() != matrixSize || matrix.cols() != matrixSize) {
    return 0.0;
  }

  vector<double> values(calculateValues(position));

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
  if (m_molecule && dynamic_cast<GaussianSet *>(m_molecule->basisSet()))
    return true;
  else
    return false;
}

inline bool GaussianSetTools::isSmall(double val) const
{
  if (val > -1e-20 && val < 1e-20)
    return true;
  else
    return false;
}

inline vector<double> GaussianSetTools::calculateValues(const Vector3 &position) const
{
  m_basis->initCalculation();
  size_t atomsSize = m_molecule->atomCount();
  size_t basisSize = m_basis->symmetry().size();
  const std::vector<int> &basis = m_basis->symmetry();
  const std::vector<unsigned int> &atomIndices = m_basis->atomIndices();
  vector<Vector3> deltas;
  vector<double> dr2;
  deltas.reserve(atomsSize);
  dr2.reserve(atomsSize);

  // Calculate our position
  Vector3 pos(position * ANGSTROM_TO_BOHR);

  // Calculate the deltas for the position
  for (size_t i = 0; i < atomsSize; ++i) {
    deltas.push_back(pos - (m_molecule->atom(i).position3d() * ANGSTROM_TO_BOHR));
    dr2.push_back(deltas[i].squaredNorm());
  }

  // Allocate space for the values to be calculated.
  size_t matrixSize = m_basis->moMatrix().rows();
  vector<double> values;
  values.resize(matrixSize, 0.0);

  // Now calculate the values at this point in space
  for (size_t i = 0; i < basisSize; ++i) {
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
    default:
      // Not handled - return a zero contribution
      ;
    }
  }

  return values;
}

inline void GaussianSetTools::pointS(unsigned int moIndex, double dr2,
                                     vector<double> &values) const
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

inline void GaussianSetTools::pointP(unsigned int moIndex, const Vector3 &delta,
                                     double dr2, vector<double> &values) const
{
  // P type orbitals have three components and each component has a different
  // independent MO weighting. Many things can be cached to save time though.
  unsigned int baseIndex = m_basis->moIndices()[moIndex];
  Vector3 components(Vector3::Zero());

  // Now iterate through the P type GTOs and sum their contributions
  unsigned int cIndex = m_basis->cIndices()[moIndex];
  for (unsigned int i = m_basis->gtoIndices()[moIndex];
       i < m_basis->gtoIndices()[moIndex + 1]; ++i) {
    double tmpGTO = exp(-m_basis->gtoA()[i] * dr2);
    for (unsigned int j = 0; j < 3; ++j) {
      //m_values[baseIndex + i] = m_basis->gtoCN()[cIndex++] * tmpGTO;
      components[j] += m_basis->gtoCN()[cIndex++] * tmpGTO;
    }
  }
  for (unsigned int i = 0; i < 3; ++i)
    values[baseIndex + i] = components[i] * delta[i];
}

inline void GaussianSetTools::pointD(unsigned int moIndex, const Vector3 &delta,
                                     double dr2, vector<double> &values) const
{
  // D type orbitals have six components and each component has a different
  // independent MO weighting. Many things can be cached to save time though.
  unsigned int baseIndex = m_basis->moIndices()[moIndex];

  double components[6] = { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 };

  vector<double> &gtoA = m_basis->gtoA();
  vector<double> &gtoCN = m_basis->gtoCN();

  // Now iterate through the D type GTOs and sum their contributions
  unsigned int cIndex = m_basis->cIndices()[moIndex];
  for (unsigned int i = m_basis->gtoIndices()[moIndex];
       i < m_basis->gtoIndices()[moIndex + 1]; ++i) {
    // Calculate the common factor
    double tmpGTO = exp(-gtoA[i] * dr2);
    for (int j = 0; j < 6; ++j)
      components[j] += gtoCN[cIndex++] * tmpGTO;
  }

  double componentsD[6] = {
    delta.x() * delta.x(),    // xx
    delta.y() * delta.y(),    // yy
    delta.z() * delta.z(),    // zz
    delta.x() * delta.y(),    // xy
    delta.x() * delta.z(),    // xz
    delta.y() * delta.z()};   // yz

  for (int i = 0; i < 6; ++i)
    values[baseIndex + i] += components[i] * componentsD[i];
}

inline void GaussianSetTools::pointD5(unsigned int moIndex,
                                      const Vector3 &delta,
                                      double dr2, vector<double> &values) const
{
  // D type orbitals have five components and each component has a different
  // MO weighting. Many things can be cached to save time.
  unsigned int baseIndex = m_basis->moIndices()[moIndex];
  double components[5] = { 0.0, 0.0, 0.0, 0.0, 0.0 };

  vector<double> &gtoA = m_basis->gtoA();
  vector<double> &gtoCN = m_basis->gtoCN();

  // Now iterate through the D type GTOs and sum their contributions
  unsigned int cIndex = m_basis->cIndices()[moIndex];
  for (unsigned int i = m_basis->gtoIndices()[moIndex];
       i < m_basis->gtoIndices()[moIndex + 1]; ++i) {
    // Calculate the common factor
    double tmpGTO = exp(-gtoA[i] * dr2);
    for (int j = 0; j < 6; ++j)
      components[j] += gtoCN[cIndex++] * tmpGTO;
  }

  // Calculate the prefactors
  double xx = delta.x() * delta.x();
  double yy = delta.y() * delta.y();
  double zz = delta.z() * delta.z();
  double xy = delta.x() * delta.y();
  double xz = delta.x() * delta.z();
  double yz = delta.y() * delta.z();

  double componentsD[5] = {
    zz - dr2,      // 0
    xz,            // 1p
    yz,            // 1n
    xx - yy,       // 2p
    xy};           // 2n

  for (int i = 0; i < 5; ++i)
    values[baseIndex + i] += componentsD[i] * components[i];
}

} // End Core namespace
} // End Avogadro namespace
