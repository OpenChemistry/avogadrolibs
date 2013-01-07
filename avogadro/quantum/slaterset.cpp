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

#ifdef WIN32
#define _USE_MATH_DEFINES
#include <math.h> // needed for M_PI
#endif

#include <avogadro/qtgui/cube.h>

//#include <Eigen/Array>
#include <Eigen/Eigenvalues>
#include <Eigen/LU>
#include <Eigen/QR>

#include <cmath>

#include <QtCore/QtConcurrentMap>
#include <QtCore/QFuture>
#include <QtCore/QFutureWatcher>
#include <QtCore/QReadWriteLock>
#include <QtCore/QDebug>

using std::vector;
using Eigen::Vector3d;
using Eigen::Vector3i;
using Eigen::MatrixXd;
using Eigen::SelfAdjointEigenSolver;

namespace Avogadro {
namespace Quantum {

struct SlaterShell
{
  SlaterSet *set;    // A pointer to the SlaterSet, cannot write to member vars
  Cube *cube;        // The target cube, used to initialise temp cubes too
  unsigned int pos;  // The index of position of the point to calculate the MO for
  unsigned int state;// The MO number to calculate
};

using std::vector;

static const double BOHR_TO_ANGSTROM = 0.529177249;
static const double ANGSTROM_TO_BOHR = 1.0 / 0.529177249;

SlaterSet::SlaterSet() : m_initialized(false)
{
}

SlaterSet::~SlaterSet()
{

}

bool SlaterSet::addAtoms(const std::vector<Eigen::Vector3d> &pos)
{
  m_atomPos = pos;
  return true;
}

bool SlaterSet::addSlaterIndices(const std::vector<int> &i)
{
  m_slaterIndices = i;
  return true;
}

bool SlaterSet::addSlaterTypes(const std::vector<int> &t)
{
  m_slaterTypes = t;
  return true;
}

bool SlaterSet::addZetas(const std::vector<double> &zetas)
{
  m_zetas = zetas;
  return true;
}

bool SlaterSet::addPQNs(const std::vector<int> &pqns)
{
  m_pqns = pqns;
  return true;
}

bool SlaterSet::addOverlapMatrix(const Eigen::MatrixXd &m)
{
  m_overlap.resize(m.rows(), m.cols());
  m_overlap = m;
  return true;
}

bool SlaterSet::addEigenVectors(const Eigen::MatrixXd &e)
{
  m_eigenVectors.resize(e.rows(), e.cols());
  m_eigenVectors = e;
  return true;
}

bool SlaterSet::addDensityMatrix(const Eigen::MatrixXd &d)
{
  m_density.resize(d.rows(), d.cols());
  m_density = d;
  return true;
}

unsigned int SlaterSet::numMOs()
{
  return static_cast<unsigned int>(m_overlap.cols());
}

inline bool SlaterSet::isSmall(double val)
{
  if (val > -1e-15 && val < 1e-15)
    return true;
  else
    return false;
}

unsigned int SlaterSet::factorial(unsigned int n)
{
  if (n <= 1)
    return n;
  return (n * factorial(n - 1));
}

void SlaterSet::outputAll()
{

}

bool SlaterSet::calculateCubeAlphaMO(Cube *, unsigned int)
{
  return false;
}

bool SlaterSet::calculateCubeBetaMO(Cube *, unsigned int)
{
  return false;
}

bool SlaterSet::calculateCubeMO(Cube *cube, unsigned int state)
{
  // Set up the calculation and ideally use the new QtConcurrent code to
  // multithread the calculation...
  if (state < 1 || static_cast<int>(state) > m_overlap.rows())
    return false;

  if (!m_initialized)
    initialize();

  // It is more efficient to process each shell over the entire cube than it
  // is to process each MO at each point in the cube. This is probably the best
  // point at which to multithread too - QtConcurrent!
  m_slaterShells.resize(static_cast<int>(cube->data()->size()));

  qDebug() << "Number of points:" << m_slaterShells.size();

  for (int i = 0; i < m_slaterShells.size(); ++i) {
    m_slaterShells[i].set = this;
    m_slaterShells[i].cube = cube;
    m_slaterShells[i].pos = i;
    m_slaterShells[i].state = state;
  }

  // Lock the cube until we are done.
  cube->lock()->lockForWrite();

  // Set the cube type
  cube->setCubeType(Cube::MO);

  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));

  // The main part of the mapped reduced function...
  m_future = QtConcurrent::map(m_slaterShells, SlaterSet::processPoint);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);

  return true;
}

bool SlaterSet::calculateCubeDensity(Cube *cube)
{
  // Set up the calculation and ideally use the new QtConcurrent code to
  // multithread the calculation...
  if (!m_initialized)
    initialize();

  // It is more efficient to process each shell over the entire cube than it
  // is to process each MO at each point in the cube. This is probably the best
  // point at which to multithread too - QtConcurrent!
  m_slaterShells.resize(static_cast<int>(cube->data()->size()));

  qDebug() << "Number of points for density:" << m_slaterShells.size();

  for (int i = 0; i < m_slaterShells.size(); ++i) {
    m_slaterShells[i].set = this;
    m_slaterShells[i].cube = cube;
    m_slaterShells[i].pos = i;
    m_slaterShells[i].state = 0;
  }

  // Lock the cube until we are done.
  cube->lock()->lockForWrite();

  // Set the cube type
  cube->setCubeType(Cube::ElectronDensity);

  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));

  // The main part of the mapped reduced function...
  m_future = QtConcurrent::map(m_slaterShells, SlaterSet::processDensity);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);

  return true;
}

bool SlaterSet::calculateCubeSpinDensity(Cube *)
{
  return false;
}

BasisSet * SlaterSet::clone()
{
  SlaterSet *result = new SlaterSet();
  result->m_atomPos = this->m_atomPos;
  result->m_slaterIndices = this->m_slaterIndices;
  result->m_zetas = this->m_zetas;
  result->m_pqns = this->m_pqns;
  result->m_PQNs = this->m_PQNs;

  result->m_factors = this->m_factors;
  result->m_overlap = this->m_overlap;
  result->m_eigenVectors = this->m_eigenVectors;
  result->m_density = this->m_density;
  result->m_normalized = this->m_normalized;
  result->m_initialized = this->m_initialized;

  // Skip tmp variables
  return result;
}

void SlaterSet::calculationComplete()
{
  disconnect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));
  qDebug() << m_slaterShells[0].cube->data()->at(0) << m_slaterShells[0].cube->data()->at(1);
  qDebug() << "Calculation complete - cube map...";
  m_slaterShells[0].cube->lock()->unlock();
}

bool SlaterSet::initialize()
{
  m_normalized.resize(m_overlap.cols(), m_overlap.rows());

  SelfAdjointEigenSolver<MatrixXd> s(m_overlap);
  MatrixXd p = s.eigenvectors();
  MatrixXd m = p * s.eigenvalues().array().inverse().array().sqrt()
                    .matrix().asDiagonal() * p.inverse();
  m_normalized = m * m_eigenVectors;

  if (!(m_overlap*m*m).eval().isIdentity())
    qDebug() << "Identity test FAILED - do you need a newer version of Eigen?";
  //    std::cout << m_normalized << std::endl << std::endl;
  //    std::cout << s.eigenvalues() << std::endl << std::endl;
  //    std::cout << m_overlap << std::endl << std::endl;
  //    std::cout << s.eigenvalues().minCoeff() << ' ' << s.eigenvalues().maxCoeff() << std::endl << std::endl;

  m_factors.resize(m_zetas.size());
  m_PQNs = m_pqns;
  // Calculate the normalizations of the orbitals
  for (unsigned int i = 0; i < m_zetas.size(); ++i) {
    switch (m_slaterTypes[i]) {
    case S:
      m_factors[i] = pow(2.0 * m_zetas[i], m_pqns[i] + 0.5) *
          sqrt(1.0 / (4.0*M_PI) / factorial(2*m_pqns[i]));
      m_PQNs[i] -= 1;
      break;
    case PX:
    case PY:
    case PZ:
      m_factors[i] = pow(2.0 * m_zetas[i], m_pqns[i] + 0.5) *
          sqrt(3.0 / (4.0*M_PI) / factorial(2*m_pqns[i]));
      m_PQNs[i] -= 2;
      break;
    case X2:
      m_factors[i] = 0.5 * pow(2.0 * m_zetas[i], m_pqns[i] + 0.5) *
          sqrt(15.0 / (4.0*M_PI) / factorial(2*m_pqns[i]));
      m_PQNs[i] -= 3;
      break;
    case XZ:
      m_factors[i] = pow(2.0 * m_zetas[i], m_pqns[i] + 0.5) *
          sqrt(15.0 / (4.0*M_PI) / factorial(2*m_pqns[i]));
      m_PQNs[i] -= 3;
      break;
    case Z2:
      m_factors[i] = (0.5/sqrt(3.0)) * pow(2.0 * m_zetas[i], m_pqns[i] + 0.5) *
          sqrt(15.0 / (4.0*M_PI) / factorial(2*m_pqns[i]));
      m_PQNs[i] -= 3;
      break;
    case YZ:
    case XY:
      m_factors[i] = pow(2.0 * m_zetas[i], m_pqns[i] + 0.5) *
          sqrt(15.0 / (4.0*M_PI) / factorial(2*m_pqns[i]));
      m_PQNs[i] -= 3;
      break;
    default:
      qDebug() << "Orbital" << i << "not handled, type" << m_slaterTypes[i];
    }
  }
  // Convert the exponents into Angstroms
  for (unsigned int i = 0; i < m_zetas.size(); ++i)
    m_zetas[i] = m_zetas[i] / BOHR_TO_ANGSTROM;

  m_initialized = true;

  return true;
}

void SlaterSet::processPoint(SlaterShell &shell)
{
  SlaterSet *set = shell.set;
  unsigned int atomsSize = static_cast<unsigned int>(set->m_atomPos.size());
  unsigned int basisSize = static_cast<unsigned int>(set->m_zetas.size());

  vector<Vector3d> deltas;
  vector<double> dr;
  deltas.reserve(atomsSize);
  dr.reserve(atomsSize);

  // Simply the row of the matrix to operate on
  unsigned int indexMO = shell.state - 1;

  // Calculate our position
  Vector3d pos = shell.cube->position(shell.pos);// * ANGSTROM_TO_BOHR;

  // Calculate the deltas for the position
  for (unsigned int i = 0; i < atomsSize; ++i) {
    deltas.push_back(pos - set->m_atomPos[i]);
    dr.push_back(deltas[i].norm());
  }

  // Now calculate the value at this point in space
  double tmp = 0.0;
  for (unsigned int i = 0; i < basisSize; ++i) {
    tmp += pointSlater(shell.set, deltas[set->m_slaterIndices[i]],
                       dr[set->m_slaterIndices[i]], i, indexMO);
  }
  // Set the value
  shell.cube->setValue(shell.pos, tmp);
}

void SlaterSet::processDensity(SlaterShell &shell)
{
  // Calculate the electron density
  SlaterSet *set = shell.set;
  unsigned int atomsSize = static_cast<unsigned int>(set->m_atomPos.size());
  unsigned int basisSize = static_cast<unsigned int>(set->m_zetas.size());
  unsigned int matrixSize = static_cast<unsigned int>(set->m_density.rows());

  vector<Vector3d> deltas;
  vector<double> dr;
  deltas.reserve(atomsSize);
  dr.reserve(atomsSize);

  // Calculate our position
  Vector3d pos = shell.cube->position(shell.pos);// * ANGSTROM_TO_BOHR;

  // Calculate the deltas for the position
  for (unsigned int i = 0; i < atomsSize; ++i) {
    deltas.push_back(pos - set->m_atomPos[i]);
    dr.push_back(deltas[i].norm());
  }

  // Precompute the factor * exp (-zeta * drs)
  vector<double> expZetas(basisSize);
  for (unsigned int i = 0; i < basisSize; ++i) {
    expZetas[i] = exp(- set->m_zetas[i] * dr[set->m_slaterIndices[i]]);
  }

  // Now calculate the value of the density at this point in space
  double rho = 0.0;
  for (unsigned int i = 0; i < matrixSize; ++i) {
    // Calculate the off-diagonal parts of the matrix
    for (unsigned int j = 0; j < i; ++j) {
      if (isSmall(set->m_density.coeffRef(i, j))) continue;
      double a = 0.0, b = 0.0;
      // Do the first basis
      a = calcSlater(shell.set, deltas[set->m_slaterIndices[i]],
                     dr[set->m_slaterIndices[i]], i);
      b = calcSlater(shell.set, deltas[set->m_slaterIndices[j]],
                     dr[set->m_slaterIndices[j]], j);
      rho += 2.0 * set->m_density.coeffRef(i, j) * (a*b);
    }
    // Now calculate the matrix diagonal
    double tmp = 0.0;
    tmp = calcSlater(shell.set, deltas[set->m_slaterIndices[i]],
                     dr[set->m_slaterIndices[i]], i);
    rho += set->m_density.coeffRef(i, i) * (tmp*tmp);
  }
  // Set the value
  shell.cube->setValue(shell.pos, rho);
}

inline double SlaterSet::pointSlater(SlaterSet *set, const Eigen::Vector3d &delta,
                                     double dr, unsigned int slater,
                                     unsigned int indexMO)
{
  if (isSmall(set->m_normalized.coeffRef(slater, indexMO)))
    return 0.0;
  double tmp = set->m_normalized.coeffRef(slater, indexMO) *
      set->m_factors[slater] * exp(- set->m_zetas[slater] * dr);
  // Radial part with effective PQNs
  for (int i = 0; i < set->m_PQNs[slater]; ++i)
    tmp *= dr;
  switch (set->m_slaterTypes[slater]) {
  case S:
    break;
  case PX:
    tmp *= delta.x();
    break;
  case PY:
    tmp *= delta.y();
    break;
  case PZ:
    tmp *= delta.z();
    break;
  case X2: // (x^2 - y^2)r^n
    tmp *= delta.x() * delta.x() - delta.y() * delta.y();
    break;
  case XZ: // xzr^n
    tmp *= delta.x() * delta.z();
    break;
  case Z2: // (2z^2 - x^2 - y^2)r^n
    tmp *= 2.0 * delta.z() * delta.z() - delta.x() * delta.x()
        - delta.y() * delta.y();
    break;
  case YZ: // yzr^n
    tmp *= delta.y() * delta.z();
    break;
  case XY: // xyr^n
    tmp *= delta.x() * delta.y();
    break;
  default:
    return 0.0;
  }
  return tmp;
}

inline double SlaterSet::pointSlater(SlaterSet *set, const Eigen::Vector3d &delta,
                                     double dr, unsigned int slater,
                                     unsigned int indexMO, double expZeta)
{
  if (isSmall(set->m_normalized.coeffRef(slater, indexMO)))
    return 0.0;
  double tmp = set->m_normalized.coeffRef(slater, indexMO) * expZeta;
  // Radial part with effective PQNs
  for (int i = 0; i < set->m_PQNs[slater]; ++i)
    tmp *= dr;
  switch (set->m_slaterTypes[slater]) {
  case S:
    break;
  case PX:
    tmp *= delta.x();
    break;
  case PY:
    tmp *= delta.y();
    break;
  case PZ:
    tmp *= delta.z();
    break;
  case X2: // (x^2 - y^2)r^n
    tmp *= delta.x() * delta.x() - delta.y() * delta.y();
    break;
  case XZ: // xzr^n
    tmp *= delta.x() * delta.z();
    break;
  case Z2: // (2z^2 - x^2 - y^2)r^n
    tmp *= 2.0 * delta.z() * delta.z() - delta.x() * delta.x()
        - delta.y() * delta.y();
    break;
  case YZ: // yzr^n
    tmp *= delta.y() * delta.z();
    break;
  case XY: // xyr^n
    tmp *= delta.x() * delta.y();
    break;
  default:
    return 0.0;
  }
  return tmp;
}

inline double SlaterSet::calcSlater(SlaterSet *set, const Eigen::Vector3d &delta,
                                    double dr, unsigned int slater)
{
  double tmp = set->m_factors[slater] * exp(- set->m_zetas[slater] * dr);
  // Radial part with effective PQNs
  for (int i = 0; i < set->m_PQNs[slater]; ++i)
    tmp *= dr;
  switch (set->m_slaterTypes[slater]) {
  case S:
    break;
  case PX:
    tmp *= delta.x();
    break;
  case PY:
    tmp *= delta.y();
    break;
  case PZ:
    tmp *= delta.z();
    break;
  case X2: // (x^2 - y^2)r^n
    tmp *= delta.x() * delta.x() - delta.y() * delta.y();
    break;
  case XZ: // xzr^n
    tmp *= delta.x() * delta.z();
    break;
  case Z2: // (2z^2 - x^2 - y^2)r^n
    tmp *= 2.0 * delta.z() * delta.z() - delta.x() * delta.x()
        - delta.y() * delta.y();
    break;
  case YZ: // yzr^n
    tmp *= delta.y() * delta.z();
    break;
  case XY: // xyr^n
    tmp *= delta.x() * delta.y();
    break;
  default:
    return 0.0;
  }
  return tmp;
}

} // End namespace Quantum
} // End namespace Avogadro
