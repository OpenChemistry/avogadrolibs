/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2008-2009 Marcus D. Hanwell
  Copyright 2010-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "slaterset.h"

#include <cmath>
#include <iostream>

#include <Eigen/LU>

using std::vector;
using std::cout;
using std::endl;
using Eigen::SelfAdjointEigenSolver;

namespace Avogadro {
namespace Core {

SlaterSet::SlaterSet() : m_initialized(false)
{
}

SlaterSet::~SlaterSet()
{
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

unsigned int SlaterSet::molecularOrbitalCount(ElectronType)
{
  return static_cast<unsigned int>(m_overlap.cols());
}

void SlaterSet::outputAll()
{
}

void SlaterSet::initCalculation()
{
  if (m_initialized)
    return;

  m_normalized.resize(m_overlap.cols(), m_overlap.rows());

  SelfAdjointEigenSolver<MatrixX> s(m_overlap);
  MatrixX p = s.eigenvectors();
  MatrixX m =
    p * s.eigenvalues().array().inverse().array().sqrt().matrix().asDiagonal() *
    p.inverse();
  m_normalized = m * m_eigenVectors;

  if (!(m_overlap * m * m).eval().isIdentity())
    cout << "Identity test FAILED - do you need a newer version of Eigen?\n";

  m_factors.resize(m_zetas.size());
  m_PQNs = m_pqns;
  // Calculate the normalizations of the orbitals.
  for (size_t i = 0; i < m_zetas.size(); ++i) {
    switch (m_slaterTypes[i]) {
      case S:
        m_factors[i] = pow(2.0 * m_zetas[i], m_pqns[i] + 0.5) *
                       sqrt(1.0 / (4.0 * M_PI) / factorial(2 * m_pqns[i]));
        m_PQNs[i] -= 1;
        break;
      case PX:
      case PY:
      case PZ:
        m_factors[i] = pow(2.0 * m_zetas[i], m_pqns[i] + 0.5) *
                       sqrt(3.0 / (4.0 * M_PI) / factorial(2 * m_pqns[i]));
        m_PQNs[i] -= 2;
        break;
      case X2:
        m_factors[i] = 0.5 * pow(2.0 * m_zetas[i], m_pqns[i] + 0.5) *
                       sqrt(15.0 / (4.0 * M_PI) / factorial(2 * m_pqns[i]));
        m_PQNs[i] -= 3;
        break;
      case XZ:
        m_factors[i] = pow(2.0 * m_zetas[i], m_pqns[i] + 0.5) *
                       sqrt(15.0 / (4.0 * M_PI) / factorial(2 * m_pqns[i]));
        m_PQNs[i] -= 3;
        break;
      case Z2:
        m_factors[i] = (0.5 / sqrt(3.0)) *
                       pow(2.0 * m_zetas[i], m_pqns[i] + 0.5) *
                       sqrt(15.0 / (4.0 * M_PI) / factorial(2 * m_pqns[i]));
        m_PQNs[i] -= 3;
        break;
      case YZ:
      case XY:
        m_factors[i] = pow(2.0 * m_zetas[i], m_pqns[i] + 0.5) *
                       sqrt(15.0 / (4.0 * M_PI) / factorial(2 * m_pqns[i]));
        m_PQNs[i] -= 3;
        break;
      default:
        cout << "Orbital " << i << " not handled, type " << m_slaterTypes[i]
             << endl;
    }
  }
  // Convert the exponents into Angstroms
  for (size_t i = 0; i < m_zetas.size(); ++i)
    m_zetas[i] = m_zetas[i] / BOHR_TO_ANGSTROM_D;

  m_initialized = true;
}

inline unsigned int SlaterSet::factorial(unsigned int n)
{
  if (n <= 1)
    return n;
  return (n * factorial(n - 1));
}

} // End namespace Core
} // End namespace Avogadro
