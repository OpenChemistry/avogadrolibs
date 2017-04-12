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

#include "slatersettools.h"

#include "molecule.h"
#include "slaterset.h"

#include <iostream>

using std::cout;
using std::endl;

using std::vector;

namespace Avogadro {
namespace Core {

SlaterSetTools::SlaterSetTools(Molecule* mol) : m_molecule(mol)
{
  if (m_molecule)
    m_basis = dynamic_cast<SlaterSet*>(m_molecule->basisSet());
}

SlaterSetTools::~SlaterSetTools()
{
}

double SlaterSetTools::calculateMolecularOrbital(const Vector3& position,
                                                 int mo) const
{
  if (mo > static_cast<int>(m_basis->molecularOrbitalCount()))
    return 0.0;

  vector<double> values(calculateValues(position));

  const MatrixX& matrix = m_basis->normalizedMatrix();
  int matrixSize(static_cast<int>(matrix.rows()));
  int indexMO(mo - 1);

  // Now calculate the value of the density at this point in space
  double result(0.0);
  for (int i = 0; i < matrixSize; ++i)
    result += matrix(i, indexMO) * values[i];

  return result;
}

double SlaterSetTools::calculateElectronDensity(const Vector3& position) const
{
  const MatrixX& matrix = m_basis->densityMatrix();
  int matrixSize(static_cast<int>(m_basis->normalizedMatrix().rows()));
  if (matrix.rows() != matrixSize || matrix.cols() != matrixSize)
    return 0.0;

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

double SlaterSetTools::calculateSpinDensity(const Vector3&) const
{
  return 0.0;
}

bool SlaterSetTools::isValid() const
{
  if (m_molecule && dynamic_cast<SlaterSet*>(m_molecule->basisSet()))
    return true;
  else
    return false;
}

inline bool SlaterSetTools::isSmall(double val) const
{
  if (val > -1e-20 && val < 1e-20)
    return true;
  else
    return false;
}

vector<double> SlaterSetTools::calculateValues(const Vector3& position) const
{
  m_basis->initCalculation();

  Index atomsSize = m_molecule->atomCount();
  size_t basisSize = m_basis->zetas().size();

  const vector<int>& slaterIndices = m_basis->slaterIndices();
  const vector<int>& slaterTypes = m_basis->slaterTypes();
  const vector<int>& PQNs = m_basis->PQNs();
  const vector<double>& factors = m_basis->factors();
  const vector<double>& zetas = m_basis->zetas();

  vector<Vector3> deltas;
  vector<double> dr2;
  deltas.reserve(atomsSize);
  dr2.reserve(atomsSize);

  // Calculate the deltas for the position
  for (Index i = 0; i < atomsSize; ++i) {
    deltas.push_back(position - m_molecule->atom(i).position3d());
    dr2.push_back(deltas[i].squaredNorm());
  }

  // Allocate space for the values to be calculated.
  vector<double> values;
  values.resize(basisSize);

  // Now calculate the values at this point in space
  for (size_t i = 0; i < basisSize; ++i) {
    double dr(dr2[slaterIndices[i]]);
    Vector3 delta(deltas[slaterIndices[i]]);
    values[i] = factors[i] * exp(-zetas[i] * dr);
    // Radial part with effective PQNs
    for (int j = 0; j < PQNs[i]; ++j)
      values[i] *= dr;
    switch (slaterTypes[i]) {
      case SlaterSet::S:
        break;
      case SlaterSet::PX:
        values[i] *= delta.x();
        break;
      case SlaterSet::PY:
        values[i] *= delta.y();
        break;
      case SlaterSet::PZ:
        values[i] *= delta.z();
        break;
      case SlaterSet::X2: // (x^2 - y^2)r^n
        values[i] *= delta.x() * delta.x() - delta.y() * delta.y();
        break;
      case SlaterSet::XZ: // xzr^n
        values[i] *= delta.x() * delta.z();
        break;
      case SlaterSet::Z2: // (2z^2 - x^2 - y^2)r^n
        values[i] *= 2.0 * delta.z() * delta.z() - delta.x() * delta.x() -
                     delta.y() * delta.y();
        break;
      case SlaterSet::YZ: // yzr^n
        values[i] *= delta.y() * delta.z();
        break;
      case SlaterSet::XY: // xyr^n
        values[i] *= delta.x() * delta.y();
        break;
      default:
        values[i] = 0.0;
    }
  }

  return values;
}

} // End Core namespace
} // End Avogadro namespace
