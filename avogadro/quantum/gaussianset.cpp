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

#include "gaussianset.h"

#ifdef WIN32
#define _USE_MATH_DEFINES
#include <math.h> // needed for M_PI
#endif

#include <avogadro/qtgui/cube.h>

#include <cmath>
#include <iostream>

#include <QtCore/QtConcurrentMap>
#include <QtCore/QFuture>
#include <QtCore/QFutureWatcher>
#include <QtCore/QReadWriteLock>
#include <QtCore/QDebug>

using std::vector;
using Eigen::Vector3d;
using Eigen::Vector3i;
using Eigen::MatrixXd;

namespace Avogadro {
namespace Quantum {

struct GaussianShell
{
  GaussianSet *set;  // A pointer to the GaussianSet, cannot write to member vars
  Cube *tCube;       // The target cube, used to initialise temp cubes too
  unsigned int pos;  // The index ofposition of the point to calculate the MO for
  unsigned int state;// The MO number to calculate
};

static const double BOHR_TO_ANGSTROM = 0.529177249;
static const double ANGSTROM_TO_BOHR = 1.0 / BOHR_TO_ANGSTROM;

GaussianSet::GaussianSet() : m_numMOs(0), m_numAlphaMOs(0), m_numBetaMOs(0),
    m_numAtoms(0), m_init(false), m_cube(0), m_gaussianShells(0)
{
}

GaussianSet::~GaussianSet()
{
}

unsigned int GaussianSet::addAtom(const Vector3d& pos, int atomicNumber)
{
  m_init = false;
  // Add to the new data structure, delete the old soon
  Core::Atom a = m_molecule.addAtom(static_cast<unsigned char>(atomicNumber));
  a.setPosition3d(pos);
  return static_cast<unsigned int>(a.index());
}

unsigned int GaussianSet::addBasis(unsigned int atom, orbital type)
{
  // Count the number of independent basis functions
  switch (type) {
  case S:
    m_numMOs++;
    break;
  case P:
    m_numMOs += 3;
    break;
  case SP:
    m_numMOs += 4;
    break;
  case D:
    m_numMOs += 6;
    break;
  case D5:
    m_numMOs += 5;
    break;
  case F:
    m_numMOs += 8;
    break;
  case F7:
    m_numMOs += 7;
    break;
  default:
    // Should never hit here
    ;
  }
  m_init = false;

  // Add to the new data structure, delete the old soon
  m_symmetry.push_back(type);
  m_atomIndices.push_back(atom);
  return static_cast<unsigned int>(m_symmetry.size() - 1);
}

unsigned int GaussianSet::addGTO(unsigned int, double c, double a)
{
  // Use the new data structure
  if (m_gtoIndices.size() < m_atomIndices.size()) {
    // First GTO added for this basis - add the gto index
    m_gtoIndices.push_back(static_cast<unsigned int>(m_gtoA.size()));
  }
  m_gtoA.push_back(a);
  m_gtoC.push_back(c);

  return static_cast<unsigned int>(m_gtoA.size() - 1);
}

void GaussianSet::addMOs(const vector<double>& MOs)
{
  m_init = false;

  // Some programs don't output all MOs, so we take the amount of data
  // and divide by the # of AO functions
  unsigned int columns = static_cast<unsigned int>(MOs.size()) / m_numMOs;
  qDebug() << " add MOs: " << m_numMOs << columns;

  m_moMatrix.resize(m_numMOs, m_numMOs);

  for (unsigned int j = 0; j < columns; ++j)
    for (unsigned int i = 0; i < m_numMOs; ++i)
      m_moMatrix.coeffRef(i, j) = MOs[i + j*m_numMOs];
}

void GaussianSet::addAlphaMOs(const vector<double>& MOs)
{
  m_init = false;

  // Some programs don't output all MOs, so we take the amount of data
  // and divide by the # of AO functions
  unsigned int columns = static_cast<unsigned int>(MOs.size()) / m_numMOs;
  qDebug() << " add Alpha MOs: " << m_numMOs << columns;

  m_alphaMoMatrix.resize(m_numMOs, m_numMOs);

  for (unsigned int j = 0; j < columns; ++j)
    for (unsigned int i = 0; i < m_numMOs; ++i)
      m_alphaMoMatrix.coeffRef(i, j) = MOs[i + j*m_numMOs];
}

void GaussianSet::addBetaMOs(const vector<double>& MOs)
{
  m_init = false;

  // Some programs don't output all MOs, so we take the amount of data
  // and divide by the # of AO functions
  unsigned int columns = static_cast<unsigned int>(MOs.size()) / m_numMOs;
  qDebug() << " add Beta MOs: " << m_numMOs << columns;

  m_betaMoMatrix.resize(m_numMOs, m_numMOs);

  for (unsigned int j = 0; j < columns; ++j)
    for (unsigned int i = 0; i < m_numMOs; ++i)
      m_betaMoMatrix.coeffRef(i, j) = MOs[i + j*m_numMOs];
}

void GaussianSet::addMO(double)
{
  m_init = false;
}

bool GaussianSet::setDensityMatrix()
{
  //For some methods the density matrix is easily computed
  //RHF = sum_i^Nocc OccOrb_i*OccOrb_i, where Nocc is numElectrons/2
  return true;
}

bool GaussianSet::setDensityMatrix(const Eigen::MatrixXd &m)
{
  m_density.resize(m.rows(), m.cols());
  m_density = m;
  return true;
}

bool GaussianSet::setSpinDensityMatrix(const Eigen::MatrixXd &m)
{
  m_spinDensity.resize(m.rows(), m.cols());
  m_spinDensity = m;
  return true;
}

bool GaussianSet::calculateCubeMO(Cube *cube, unsigned int state)
{
  // Set up the calculation and ideally use the new QtConcurrent code to
  // multithread the calculation...
  if (state < 1 || state > static_cast<unsigned int>(m_moMatrix.rows()))
    return false;

  outputAll();
  // Must be called before calculations begin
  initCalculation();

  // Set up the points we want to calculate the density at
  m_gaussianShells =
    new QVector<GaussianShell>(static_cast<int>(cube->data()->size()));

  for (int i = 0; i < m_gaussianShells->size(); ++i) {
    (*m_gaussianShells)[i].set = this;
    (*m_gaussianShells)[i].tCube = cube;
    (*m_gaussianShells)[i].pos = i;
    (*m_gaussianShells)[i].state = state;
  }

  // Lock the cube until we are done.
  cube->lock()->lockForWrite();

  // Set the cube type
  cube->setCubeType(Cube::MO);

  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));

  // The main part of the mapped reduced function...
  m_future = QtConcurrent::map(*m_gaussianShells, GaussianSet::processPoint);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);

  return true;
}

bool GaussianSet::calculateCubeAlphaMO(Cube *cube, unsigned int state)
{
  // Set up the calculation and ideally use the new QtConcurrent code to
  // multithread the calculation...
  if (state < 1 || state > static_cast<unsigned int>(m_alphaMoMatrix.rows()))
    return false;

  outputAlphaAll();
  // Must be called before calculations begin
  initCalculation();

  // Set up the points we want to calculate the density at
  m_gaussianShells =
      new QVector<GaussianShell>(static_cast<int>(cube->data()->size()));

  for (int i = 0; i < m_gaussianShells->size(); ++i) {
    (*m_gaussianShells)[i].set = this;
    (*m_gaussianShells)[i].tCube = cube;
    (*m_gaussianShells)[i].pos = i;
    (*m_gaussianShells)[i].state = state;
  }

  // Lock the cube until we are done.
  cube->lock()->lockForWrite();

  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));

  // The main part of the mapped reduced function...
  m_future = QtConcurrent::map(*m_gaussianShells, GaussianSet::processAlphaPoint);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);

  return true;
}

bool GaussianSet::calculateCubeBetaMO(Cube *cube, unsigned int state)
{
  // Set up the calculation and ideally use the new QtConcurrent code to
  // multithread the calculation...
  if (state < 1 || state > static_cast<unsigned int>(m_betaMoMatrix.rows()))
    return false;

  outputBetaAll();
  // Must be called before calculations begin
  initCalculation();

  // Set up the points we want to calculate the density at
  m_gaussianShells =
      new QVector<GaussianShell>(static_cast<int>(cube->data()->size()));

  for (int i = 0; i < m_gaussianShells->size(); ++i) {
    (*m_gaussianShells)[i].set = this;
    (*m_gaussianShells)[i].tCube = cube;
    (*m_gaussianShells)[i].pos = i;
    (*m_gaussianShells)[i].state = state;
  }

  // Lock the cube until we are done.
  cube->lock()->lockForWrite();

  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));

  // The main part of the mapped reduced function...
  m_future = QtConcurrent::map(*m_gaussianShells, GaussianSet::processBetaPoint);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);

  return true;
}

bool GaussianSet::calculateCubeDensity(Cube *cube)
{
  if (m_density.size() == 0) {
    bool dens=generateDensity();
    if (!dens) {
      qDebug() << "Cannot calculate density -- density matrix not set.";
      return false;
    }
  }

  // FIXME Still not working, committed so others could see current state.

  // Must be called before calculations begin
  initCalculation();

  // Set up the points we want to calculate the density at
  m_gaussianShells =
    new QVector<GaussianShell>(static_cast<int>(cube->data()->size()));

  for (int i = 0; i < m_gaussianShells->size(); ++i) {
    (*m_gaussianShells)[i].set = this;
    (*m_gaussianShells)[i].tCube = cube;
    (*m_gaussianShells)[i].pos = i;
  }

  // Lock the cube until we are done.
  cube->lock()->lockForWrite();

  // Set the cube type
  cube->setCubeType(Cube::ElectronDensity);

  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));

  // The main part of the mapped reduced function...
  m_future = QtConcurrent::map(*m_gaussianShells, GaussianSet::processDensity);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);

  return true;
}

bool GaussianSet::calculateCubeSpinDensity(Cube *cube)
{
  if (m_spinDensity.size() == 0) {
    bool dens=generateSpinDensity();
    if (!dens) {
      qDebug() << "Cannot calculate spin density -- spin density matrix not set.";
      return false;
    }
  }

  // FIXME Still not working, committed so others could see current state.

  // Must be called before calculations begin
  initCalculation();

  // Set up the points we want to calculate the density at
  m_gaussianShells =
      new QVector<GaussianShell>(static_cast<int>(cube->data()->size()));

  for (int i = 0; i < m_gaussianShells->size(); ++i) {
    (*m_gaussianShells)[i].set = this;
    (*m_gaussianShells)[i].tCube = cube;
    (*m_gaussianShells)[i].pos = i;
  }

  // Lock the cube until we are done.
  cube->lock()->lockForWrite();

  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));

  // The main part of the mapped reduced function...
  m_future = QtConcurrent::map(*m_gaussianShells, GaussianSet::processSpinDensity);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);

  return true;
}

BasisSet * GaussianSet::clone()
{
  GaussianSet *result = new GaussianSet();

  result->m_symmetry = this->m_symmetry;
  result->m_atomIndices = this->m_atomIndices;
  result->m_moIndices = this->m_moIndices;
  result->m_gtoIndices = this->m_gtoIndices;
  result->m_cIndices = this->m_cIndices;
  result->m_gtoA = this->m_gtoA;
  result->m_gtoC = this->m_gtoC;
  result->m_gtoCN = this->m_gtoCN;
  result->m_moMatrix = this->m_moMatrix;
  result->m_density = this->m_density;

  result->m_numMOs = this->m_numMOs;
  result->m_numAtoms = this->m_numAtoms;
  result->m_init = this->m_init;

  // Skip tmp vars
  return result;
}

void GaussianSet::calculationComplete()
{
  disconnect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));
  (*m_gaussianShells)[0].tCube->lock()->unlock();
  delete m_gaussianShells;
  m_gaussianShells = 0;
  emit finished();
}

inline bool GaussianSet::isSmall(double val)
{
  if (val > -1e-20 && val < 1e-20)
    return true;
  else
    return false;
}

void GaussianSet::initCalculation()
{
  if (m_init)
    return;
  // This currently just involves normalising all contraction coefficients
  m_numAtoms = static_cast<unsigned int>(m_molecule.atomCount());
  m_gtoCN.clear();

  // Initialise the new data structures that are hopefully more efficient
  unsigned int indexMO = 0;
  unsigned int skip = 0; // for unimplemented shells

  m_moIndices.resize(m_symmetry.size());
  // Add a final entry to the gtoIndices
  m_gtoIndices.push_back(static_cast<unsigned int>(m_gtoA.size()));
  for(unsigned int i = 0; i < m_symmetry.size(); ++i) {
    switch (m_symmetry[i]) {
    case S:
      m_moIndices[i] = indexMO++;
      m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
      // Normalization of the S-type orbitals (normalization used in JMol)
      // (8 * alpha^3 / pi^3)^0.25 * exp(-alpha * r^2)
      for(unsigned j = m_gtoIndices[i]; j < m_gtoIndices[i+1]; ++j) {
        m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 0.75) * 0.71270547);
      }
      break;
    case P:
      m_moIndices[i] = indexMO;
      indexMO += 3;
      m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
      // Normalization of the P-type orbitals (normalization used in JMol)
      // (128 alpha^5 / pi^3)^0.25 * [x|y|z]exp(-alpha * r^2)
      for(unsigned j = m_gtoIndices[i]; j < m_gtoIndices[i+1]; ++j) {
        m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 1.25) * 1.425410941);
        m_gtoCN.push_back(m_gtoCN.back());
        m_gtoCN.push_back(m_gtoCN.back());
      }
      break;
    case D:
      // Cartesian - 6 d components
      // Order in xx, yy, zz, xy, xz, yz
      m_moIndices[i] = indexMO;
      indexMO += 6;
      m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
      // Normalization of the P-type orbitals (normalization used in JMol)
      // xx|yy|zz: (2048 alpha^7/9pi^3)^0.25 [xx|yy|zz]exp(-alpha r^2)
      // xy|xz|yz: (2048 alpha^7/pi^3)^0.25 [xy|xz|yz]exp(-alpha r^2)
      for(unsigned j = m_gtoIndices[i]; j < m_gtoIndices[i+1]; ++j) {
        m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 1.75) * 1.645922781);
        m_gtoCN.push_back(m_gtoCN.back());
        m_gtoCN.push_back(m_gtoCN.back());

        m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 1.75) * 2.850821881);
        m_gtoCN.push_back(m_gtoCN.back());
        m_gtoCN.push_back(m_gtoCN.back());
      }
      break;
    case D5:
      // Spherical - 5 d components
      // Order in d0, d+1, d-1, d+2, d-2
      // Form d(z^2-r^2), dxz, dyz, d(x^2-y^2), dxy
      m_moIndices[i] = indexMO;
      indexMO += 5;
      m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
      for(unsigned j = m_gtoIndices[i]; j < m_gtoIndices[i+1]; ++j) {
        m_gtoCN.push_back(m_gtoC[j] * pow(2048 * pow(m_gtoA[j], 7.0)
                                          / (9.0 * M_PI*M_PI*M_PI), 0.25));
        m_gtoCN.push_back(m_gtoC[j] * pow(2048 * pow(m_gtoA[j], 7.0)
                                          / (M_PI*M_PI*M_PI), 0.25));
        m_gtoCN.push_back(m_gtoCN.back());
        // I think this is correct but reaally need to check...
        m_gtoCN.push_back(m_gtoC[j] * pow(128 * pow(m_gtoA[j], 7.0)
                                          / (M_PI*M_PI*M_PI), 0.25));
        m_gtoCN.push_back(m_gtoC[j] * pow(2048 * pow(m_gtoA[j], 7.0)
                                          / (M_PI*M_PI*M_PI), 0.25));
      }
      break;
    case F:
      skip = 10;
    case F7:
      skip = 7;
    case G:
      skip = 15;
    case G9:
      skip = 9;
    case H:
      skip = 21;
    case H11:
      skip = 11;
    case I:
      skip = 28;
    case I13:
      skip = 13;

      m_moIndices[i] = indexMO;
      indexMO += skip;
      m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
      qDebug() << "Basis set not handled - results may be incorrect.";
      break;

    default:
      qDebug() << "Basis set not handled - results may be incorrect.";
    }
  }
  m_init = true;
}

/// This is the stuff we actually use right now - porting to new data structure
void GaussianSet::processPoint(GaussianShell &shell)
{
  GaussianSet *set = shell.set;
  unsigned int atomsSize = set->m_numAtoms;
  unsigned int basisSize = static_cast<unsigned int>(set->m_symmetry.size());
  std::vector<int> &basis = set->m_symmetry;
  vector<Vector3d> deltas;
  vector<double> dr2;
  deltas.reserve(atomsSize);
  dr2.reserve(atomsSize);

  unsigned int indexMO = shell.state-1;

  // Calculate our position
  Vector3d pos = shell.tCube->position(shell.pos) * ANGSTROM_TO_BOHR;
  //qDebug() << pos.x() << " " << pos.y() << " " << pos.y();

  // Calculate the deltas for the position
  for (unsigned int i = 0; i < atomsSize; ++i) {
    deltas.push_back(pos - set->m_molecule.atom(i).position3d());
    dr2.push_back(deltas[i].squaredNorm());
  }

  // Now calculate the value at this point in space
  double tmp = 0.0;
  orbType type = Doubly;
  for (unsigned int i = 0; i < basisSize; ++i) {
    switch (basis[i]) {
    case S:
      tmp += pointS(shell.set, i,
                    dr2[set->m_atomIndices[i]], indexMO, type);
      break;
    case P:
      tmp += pointP(shell.set, i, deltas[set->m_atomIndices[i]],
                    dr2[set->m_atomIndices[i]], indexMO, type);
      break;
    case D:
      tmp += pointD(shell.set, i, deltas[set->m_atomIndices[i]],
                    dr2[set->m_atomIndices[i]], indexMO , type);
      break;
    case D5:
      tmp += pointD5(shell.set, i, deltas[set->m_atomIndices[i]],
                     dr2[set->m_atomIndices[i]], indexMO, type);
      break;
    default:
      // Not handled - return a zero contribution
      ;
    }
  }
  // Set the value
  shell.tCube->setValue(shell.pos, tmp);
}

void GaussianSet::processAlphaPoint(GaussianShell &shell)
{
  GaussianSet *set = shell.set;
  unsigned int atomsSize = set->m_numAtoms;
  unsigned int basisSize = static_cast<unsigned int>(set->m_symmetry.size());
  std::vector<int> &basis = set->m_symmetry;
  vector<Vector3d> deltas;
  vector<double> dr2;
  deltas.reserve(atomsSize);
  dr2.reserve(atomsSize);

  unsigned int indexMO = shell.state-1;

  // Calculate our position
  Vector3d pos = shell.tCube->position(shell.pos) * ANGSTROM_TO_BOHR;
  //qDebug() << pos.x() << " " << pos.y() << " " << pos.y();

  // Calculate the deltas for the position
  for (unsigned int i = 0; i < atomsSize; ++i) {
    deltas.push_back(pos - set->m_molecule.atom(i).position3d());
    dr2.push_back(deltas[i].squaredNorm());
  }

  // Now calculate the value at this point in space
  double tmp = 0.0;
  orbType type = Alpha;
  for (unsigned int i = 0; i < basisSize; ++i) {
    switch (basis[i]) {
    case S:
      tmp += pointS(shell.set, i,
                    dr2[set->m_atomIndices[i]], indexMO, type);
      break;
    case P:
      tmp += pointP(shell.set, i, deltas[set->m_atomIndices[i]],
                    dr2[set->m_atomIndices[i]], indexMO, type);
      break;
    case D:
      tmp += pointD(shell.set, i, deltas[set->m_atomIndices[i]],
                    dr2[set->m_atomIndices[i]], indexMO , type);
      break;
    case D5:
      tmp += pointD5(shell.set, i, deltas[set->m_atomIndices[i]],
                     dr2[set->m_atomIndices[i]], indexMO, type);
      break;
    default:
      // Not handled - return a zero contribution
      ;
    }
  }
  // Set the value
  shell.tCube->setValue(shell.pos, tmp);
}

void GaussianSet::processBetaPoint(GaussianShell &shell)
{
  GaussianSet *set = shell.set;
  unsigned int atomsSize = set->m_numAtoms;
  unsigned int basisSize = static_cast<unsigned int>(set->m_symmetry.size());
  std::vector<int> &basis = set->m_symmetry;
  vector<Vector3d> deltas;
  vector<double> dr2;
  deltas.reserve(atomsSize);
  dr2.reserve(atomsSize);

  unsigned int indexMO = shell.state-1;

  // Calculate our position
  Vector3d pos = shell.tCube->position(shell.pos) * ANGSTROM_TO_BOHR;
  //qDebug() << pos.x() << " " << pos.y() << " " << pos.y();

  // Calculate the deltas for the position
  for (unsigned int i = 0; i < atomsSize; ++i) {
    deltas.push_back(pos - set->m_molecule.atom(i).position3d());
    dr2.push_back(deltas[i].squaredNorm());
  }

  // Now calculate the value at this point in space
  double tmp = 0.0;
  orbType type = Beta;
  for (unsigned int i = 0; i < basisSize; ++i) {
    switch (basis[i]) {
    case S:
      tmp += pointS(shell.set, i,
                    dr2[set->m_atomIndices[i]], indexMO, type);
      break;
    case P:
      tmp += pointP(shell.set, i, deltas[set->m_atomIndices[i]],
                    dr2[set->m_atomIndices[i]], indexMO, type);
      break;
    case D:
      tmp += pointD(shell.set, i, deltas[set->m_atomIndices[i]],
                    dr2[set->m_atomIndices[i]], indexMO , type);
      break;
    case D5:
      tmp += pointD5(shell.set, i, deltas[set->m_atomIndices[i]],
                     dr2[set->m_atomIndices[i]], indexMO, type);
      break;
    default:
      // Not handled - return a zero contribution
      ;
    }
  }
  // Set the value
  shell.tCube->setValue(shell.pos, tmp);
}

void GaussianSet::processDensity(GaussianShell &shell)
{
  GaussianSet *set = shell.set;
  unsigned int atomsSize = set->m_numAtoms;
  unsigned int basisSize = static_cast<unsigned int>(set->m_symmetry.size());
  unsigned int matrixSize = static_cast<unsigned int>(set->m_density.rows());
  std::vector<int> &basis = set->m_symmetry;
  vector<Vector3d> deltas;
  vector<double> dr2;
  deltas.reserve(atomsSize);
  dr2.reserve(atomsSize);

  // Calculate our position
  Vector3d pos = shell.tCube->position(shell.pos) * ANGSTROM_TO_BOHR;
  // Calculate the deltas for the position
  for (unsigned int i = 0; i < atomsSize; ++i) {
    deltas.push_back(pos - set->m_molecule.atom(i).position3d());
    dr2.push_back(deltas[i].squaredNorm());
  }

  // Calculate the basis set values at this point
  MatrixXd values(matrixSize, 1);
  for (unsigned int i = 0; i < basisSize; ++i) {
    unsigned int cAtom = set->m_atomIndices[i];
    switch (basis[i]) {
    case S:
      pointS(shell.set, dr2[cAtom], i, values);
      break;
    case P:
      pointP(shell.set, deltas[cAtom], dr2[cAtom], i, values);
      break;
    case D:
      pointD(shell.set, deltas[cAtom], dr2[cAtom], i, values);
      break;
    case D5:
      pointD5(shell.set, deltas[cAtom], dr2[cAtom], i, values);
      break;
    default:
      // Not handled - return a zero contribution
      ;
    }
  }

  // Now calculate the value of the density at this point in space
  double rho = 0.0;
  for (unsigned int i = 0; i < matrixSize; ++i) {
    // Calculate the off-diagonal parts of the matrix
    for (unsigned int j = 0; j < i; ++j) {
      rho += 2.0 * set->m_density.coeffRef(i, j)
          * (values.coeffRef(i, 0) * values.coeffRef(j, 0));
    }
    // Now calculate the matrix diagonal
    rho += set->m_density.coeffRef(i, i)
        * (values.coeffRef(i, 0) * values.coeffRef(i, 0));
  }

  // Set the value
  shell.tCube->setValue(shell.pos, rho);
}

void GaussianSet::processSpinDensity(GaussianShell &shell)
{
  GaussianSet *set = shell.set;
  unsigned int atomsSize = set->m_numAtoms;
  unsigned int basisSize = static_cast<unsigned int>(set->m_symmetry.size());
  unsigned int matrixSize =
      static_cast<unsigned int>(set->m_spinDensity.rows());
  std::vector<int> &basis = set->m_symmetry;
  vector<Vector3d> deltas;
  vector<double> dr2;
  deltas.reserve(atomsSize);
  dr2.reserve(atomsSize);

  // Calculate our position
  Vector3d pos = shell.tCube->position(shell.pos) * ANGSTROM_TO_BOHR;
  // Calculate the deltas for the position
  for (unsigned int i = 0; i < atomsSize; ++i) {
    deltas.push_back(pos - set->m_molecule.atom(i).position3d());
    dr2.push_back(deltas[i].squaredNorm());
  }

  // Calculate the basis set values at this point
  MatrixXd values(matrixSize, 1);
  for (unsigned int i = 0; i < basisSize; ++i) {
    unsigned int cAtom = set->m_atomIndices[i];
    switch (basis[i]) {
    case S:
      pointS(shell.set, dr2[cAtom], i, values);
      break;
    case P:
      pointP(shell.set, deltas[cAtom], dr2[cAtom], i, values);
      break;
    case D:
      pointD(shell.set, deltas[cAtom], dr2[cAtom], i, values);
      break;
    case D5:
      pointD5(shell.set, deltas[cAtom], dr2[cAtom], i, values);
      break;
    default:
      // Not handled - return a zero contribution
      ;
    }
  }

  // Now calculate the value of the density at this point in space
  double rho = 0.0;
  for (unsigned int i = 0; i < matrixSize; ++i) {
    // Calculate the off-diagonal parts of the matrix
    for (unsigned int j = 0; j < i; ++j) {
      rho += 2.0 * set->m_spinDensity.coeffRef(i, j)
          * (values.coeffRef(i, 0) * values.coeffRef(j, 0));
    }
    // Now calculate the matrix diagonal
    rho += set->m_spinDensity.coeffRef(i, i)
        * (values.coeffRef(i, 0) * values.coeffRef(i, 0));
  }

  // Set the value
  shell.tCube->setValue(shell.pos, rho);
}

inline double GaussianSet::pointS(GaussianSet *set, unsigned int moIndex,
                                  double dr2, unsigned int indexMO,
                                  orbType type)
{
  //determine the orbital we want
  double coeff;
  switch (type) {
  case Doubly:
    coeff = set->m_moMatrix.coeffRef(set->m_moIndices[moIndex], indexMO);
    break;
  case Alpha:
    coeff = set->m_alphaMoMatrix.coeffRef(set->m_moIndices[moIndex], indexMO);
    break;
  case Beta:
    coeff = set->m_betaMoMatrix.coeffRef(set->m_moIndices[moIndex], indexMO);
    break;
  }
  // If the MO coefficient is very small skip it
  //if (isSmall(set->m_moMatrix.coeffRef(set->m_moIndices[moIndex], indexMO))) {
  if (isSmall(coeff))
    return 0.0;

  // S type orbitals - the simplest of the calculations with one component
  double tmp = 0.0;
  unsigned int cIndex = set->m_cIndices[moIndex];
  for (unsigned int i = set->m_gtoIndices[moIndex];
       i < set->m_gtoIndices[moIndex+1]; ++i) {
    tmp += set->m_gtoCN[cIndex++] * exp(-set->m_gtoA[i] * dr2);
  }
  // There is one MO coefficient per S shell basis
  //return tmp * set->m_moMatrix.coeffRef(set->m_moIndices[moIndex], indexMO);
  return tmp * coeff;
}

inline double GaussianSet::pointP(GaussianSet *set, unsigned int moIndex,
                                  const Vector3d &delta,
                                  double dr2, unsigned int indexMO,
                                  orbType type)
{
  // P type orbitals have three components and each component has a different
  // independent MO weighting. Many things can be cached to save time though
  unsigned int baseIndex = set->m_moIndices[moIndex];
  double x = 0.0, y = 0.0, z = 0.0;


  // Now iterate through the P type GTOs and sum their contributions
  unsigned int cIndex = set->m_cIndices[moIndex];
  for (unsigned int i = set->m_gtoIndices[moIndex];
       i < set->m_gtoIndices[moIndex+1]; ++i) {
    double tmpGTO = exp(-set->m_gtoA[i] * dr2);
    x += set->m_gtoCN[cIndex++] * delta.x() * tmpGTO;
    y += set->m_gtoCN[cIndex++] * delta.y() * tmpGTO;
    z += set->m_gtoCN[cIndex++] * delta.z() * tmpGTO;
  }

  /* Calculate the prefactors for Px, Py and Pz
  double Px = set->m_moMatrix.coeffRef(baseIndex  , indexMO);
  double Py = set->m_moMatrix.coeffRef(baseIndex+1, indexMO);
  double Pz = set->m_moMatrix.coeffRef(baseIndex+2, indexMO);
  */
  double Px,Py,Pz;
  switch (type) {
  case Doubly:
    Px = set->m_moMatrix.coeffRef(baseIndex  , indexMO);
    Py = set->m_moMatrix.coeffRef(baseIndex+1, indexMO);
    Pz = set->m_moMatrix.coeffRef(baseIndex+2, indexMO);
    break;
  case Alpha:
    Px = set->m_alphaMoMatrix.coeffRef(baseIndex  , indexMO);
    Py = set->m_alphaMoMatrix.coeffRef(baseIndex+1, indexMO);
    Pz = set->m_alphaMoMatrix.coeffRef(baseIndex+2, indexMO);
    break;
  case Beta:
    Px = set->m_betaMoMatrix.coeffRef(baseIndex  , indexMO);
    Py = set->m_betaMoMatrix.coeffRef(baseIndex+1, indexMO);
    Pz = set->m_betaMoMatrix.coeffRef(baseIndex+2, indexMO);
    break;
  }

  return Px*x + Py*y + Pz*z;
}

inline double GaussianSet::pointD(GaussianSet *set, unsigned int moIndex,
                                  const Vector3d &delta,
                                  double dr2, unsigned int indexMO,
                                  orbType type)
{
  // D type orbitals have six components and each component has a different
  // independent MO weighting. Many things can be cached to save time though
  unsigned int baseIndex = set->m_moIndices[moIndex];
  double xx = 0.0, yy = 0.0, zz = 0.0, xy = 0.0, xz = 0.0, yz = 0.0;

  // Now iterate through the D type GTOs and sum their contributions
  unsigned int cIndex = set->m_cIndices[moIndex];
  for (unsigned int i = set->m_gtoIndices[moIndex];
       i < set->m_gtoIndices[moIndex+1]; ++i) {
    // Calculate the common factor
    double tmpGTO = exp(-set->m_gtoA[i] * dr2);
    xx += set->m_gtoCN[cIndex++] * tmpGTO; // Dxx
    yy += set->m_gtoCN[cIndex++] * tmpGTO; // Dyy
    zz += set->m_gtoCN[cIndex++] * tmpGTO; // Dzz
    xy += set->m_gtoCN[cIndex++] * tmpGTO; // Dxy
    xz += set->m_gtoCN[cIndex++] * tmpGTO; // Dxz
    yz += set->m_gtoCN[cIndex++] * tmpGTO; // Dyz
  }

  double Cxx,Cyy,Czz,Cxy,Cxz,Cyz;
  switch (type) {
  case Doubly:
    Cxx = set->m_moMatrix.coeffRef(baseIndex  , indexMO);
    Cyy = set->m_moMatrix.coeffRef(baseIndex+1, indexMO);
    Czz = set->m_moMatrix.coeffRef(baseIndex+2, indexMO);
    Cxy = set->m_moMatrix.coeffRef(baseIndex+3, indexMO);
    Cxz = set->m_moMatrix.coeffRef(baseIndex+4, indexMO);
    Cyz = set->m_moMatrix.coeffRef(baseIndex+5, indexMO);
    break;
  case Alpha:
    Cxx = set->m_alphaMoMatrix.coeffRef(baseIndex  , indexMO);
    Cyy = set->m_alphaMoMatrix.coeffRef(baseIndex+1, indexMO);
    Czz = set->m_alphaMoMatrix.coeffRef(baseIndex+2, indexMO);
    Cxy = set->m_alphaMoMatrix.coeffRef(baseIndex+3, indexMO);
    Cxz = set->m_alphaMoMatrix.coeffRef(baseIndex+4, indexMO);
    Cyz = set->m_alphaMoMatrix.coeffRef(baseIndex+5, indexMO);
    break;
  case Beta:
    Cxx = set->m_betaMoMatrix.coeffRef(baseIndex  , indexMO);
    Cyy = set->m_betaMoMatrix.coeffRef(baseIndex+1, indexMO);
    Czz = set->m_betaMoMatrix.coeffRef(baseIndex+2, indexMO);
    Cxy = set->m_betaMoMatrix.coeffRef(baseIndex+3, indexMO);
    Cxz = set->m_betaMoMatrix.coeffRef(baseIndex+4, indexMO);
    Cyz = set->m_betaMoMatrix.coeffRef(baseIndex+5, indexMO);
    break;
  }
  // Calculate the prefactors
  double Dxx = Cxx * delta.x()
      * delta.x();
  double Dyy = Cyy * delta.y()
      * delta.y();
  double Dzz = Czz * delta.z()
      * delta.z();
  double Dxy = Cxy * delta.x()
      * delta.y();
  double Dxz = Cxz * delta.x()
      * delta.z();
  double Dyz = Cyz * delta.y()
      * delta.z();
  return Dxx*xx + Dyy*yy + Dzz*zz + Dxy*xy + Dxz*xz + Dyz*yz;
}

inline double GaussianSet::pointD5(GaussianSet *set, unsigned int moIndex,
                                   const Vector3d &delta,
                                   double dr2, unsigned int indexMO,
                                   orbType type)
{
  // D type orbitals have five components and each component has a different
  // MO weighting. Many things can be cached to save time
  unsigned int baseIndex = set->m_moIndices[moIndex];
  double d0 = 0.0, d1p = 0.0, d1n = 0.0, d2p = 0.0, d2n = 0.0;

  // Now iterate through the D type GTOs and sum their contributions
  unsigned int cIndex = set->m_cIndices[moIndex];
  for (unsigned int i = set->m_gtoIndices[moIndex];
       i < set->m_gtoIndices[moIndex+1]; ++i) {
    // Calculate the common factor
    double tmpGTO = exp(-set->m_gtoA[i] * dr2);
    d0  += set->m_gtoCN[cIndex++] * tmpGTO;
    d1p += set->m_gtoCN[cIndex++] * tmpGTO;
    d1n += set->m_gtoCN[cIndex++] * tmpGTO;
    d2p += set->m_gtoCN[cIndex++] * tmpGTO;
    d2n += set->m_gtoCN[cIndex++] * tmpGTO;
  }

  // Calculate the prefactors
  double xx = delta.x() * delta.x();
  double yy = delta.y() * delta.y();
  double zz = delta.z() * delta.z();
  double xy = delta.x() * delta.y();
  double xz = delta.x() * delta.z();
  double yz = delta.y() * delta.z();

  double C0,C1p,C1n,C2p,C2n;
  switch (type) {
  case Doubly:
    C0  = set->m_moMatrix.coeffRef(baseIndex  , indexMO);
    C1p = set->m_moMatrix.coeffRef(baseIndex+1, indexMO);
    C1n = set->m_moMatrix.coeffRef(baseIndex+2, indexMO);
    C2p = set->m_moMatrix.coeffRef(baseIndex+3, indexMO);
    C2n = set->m_moMatrix.coeffRef(baseIndex+4, indexMO);
    break;
  case Alpha:
    C0  = set->m_alphaMoMatrix.coeffRef(baseIndex  , indexMO);
    C1p = set->m_alphaMoMatrix.coeffRef(baseIndex+1, indexMO);
    C1n = set->m_alphaMoMatrix.coeffRef(baseIndex+2, indexMO);
    C2p = set->m_alphaMoMatrix.coeffRef(baseIndex+3, indexMO);
    C2n = set->m_alphaMoMatrix.coeffRef(baseIndex+4, indexMO);
    break;
  case Beta:
    C0  = set->m_betaMoMatrix.coeffRef(baseIndex  , indexMO);
    C1p = set->m_betaMoMatrix.coeffRef(baseIndex+1, indexMO);
    C1n = set->m_betaMoMatrix.coeffRef(baseIndex+2, indexMO);
    C2p = set->m_betaMoMatrix.coeffRef(baseIndex+3, indexMO);
    C2n = set->m_betaMoMatrix.coeffRef(baseIndex+4, indexMO);
    break;
  }

  double D0  = C0  * (zz - dr2);
  double D1p = C1p * xz;
  double D1n = C1n * yz;
  double D2p = C2p * (xx - yy);
  double D2n = C2n * xy;

  return D0*d0 + D1p*d1p + D1n*d1n + D2p*d2p + D2n*d2n;
}

inline void GaussianSet::pointS(GaussianSet *set, double dr2, int basis,
                                Eigen::MatrixXd &out)
{
  // S type orbitals - the simplest of the calculations with one component
  double tmp = 0.0;
  unsigned int cIndex = set->m_cIndices[basis];
  for (unsigned int i = set->m_gtoIndices[basis];
       i < set->m_gtoIndices[basis+1]; ++i) {
    tmp += set->m_gtoCN[cIndex++] * exp(-set->m_gtoA[i] * dr2);
  }
  out.coeffRef(set->m_moIndices[basis], 0) = tmp;
}

inline void GaussianSet::pointP(GaussianSet *set, const Vector3d &delta,
                                double dr2, int basis,
                                Eigen::MatrixXd &out)
{
  double x = 0.0, y = 0.0, z = 0.0;

  // Now iterate through the P type GTOs and sum their contributions
  unsigned int cIndex = set->m_cIndices[basis];
  for (unsigned int i = set->m_gtoIndices[basis];
       i < set->m_gtoIndices[basis+1]; ++i) {
    double tmpGTO = exp(-set->m_gtoA[i] * dr2);
    x += set->m_gtoCN[cIndex++] * tmpGTO;
    y += set->m_gtoCN[cIndex++] * tmpGTO;
    z += set->m_gtoCN[cIndex++] * tmpGTO;
  }

  // Save values to the matrix
  int baseIndex = set->m_moIndices[basis];
  out.coeffRef(baseIndex  , 0) = x * delta.x();
  out.coeffRef(baseIndex+1, 0) = y * delta.y();
  out.coeffRef(baseIndex+2, 0) = z * delta.z();
}

inline void GaussianSet::pointD(GaussianSet *set, const Eigen::Vector3d &delta,
                                double dr2, int basis,
                                Eigen::MatrixXd &out)
{
  // D type orbitals have six components and each component has a different
  // independent MO weighting. Many things can be cached to save time though
  double xx = 0.0, yy = 0.0, zz = 0.0, xy = 0.0, xz = 0.0, yz = 0.0;

  // Now iterate through the D type GTOs and sum their contributions
  unsigned int cIndex = set->m_cIndices[basis];
  for (unsigned int i = set->m_gtoIndices[basis];
       i < set->m_gtoIndices[basis+1]; ++i) {
    // Calculate the common factor
    double tmpGTO = exp(-set->m_gtoA[i] * dr2);
    xx += set->m_gtoCN[cIndex++] * tmpGTO; // Dxx
    yy += set->m_gtoCN[cIndex++] * tmpGTO; // Dyy
    zz += set->m_gtoCN[cIndex++] * tmpGTO; // Dzz
    xy += set->m_gtoCN[cIndex++] * tmpGTO; // Dxy
    xz += set->m_gtoCN[cIndex++] * tmpGTO; // Dxz
    yz += set->m_gtoCN[cIndex++] * tmpGTO; // Dyz
  }

  // Save values to the matrix
  int baseIndex = set->m_moIndices[basis];
  out.coeffRef(baseIndex  , 0) = delta.x() * delta.x() * xx;
  out.coeffRef(baseIndex+1, 0) = delta.y() * delta.y() * yy;
  out.coeffRef(baseIndex+2, 0) = delta.z() * delta.z() * zz;
  out.coeffRef(baseIndex+3, 0) = delta.x() * delta.y() * xy;
  out.coeffRef(baseIndex+4, 0) = delta.x() * delta.z() * xz;
  out.coeffRef(baseIndex+5, 0) = delta.y() * delta.z() * yz;
}

inline void GaussianSet::pointD5(GaussianSet *set, const Eigen::Vector3d &delta,
                                 double dr2, int basis,
                                 Eigen::MatrixXd &out)
{
  // D type orbitals have six components and each component has a different
  // independent MO weighting. Many things can be cached to save time though
  double d0 = 0.0, d1p = 0.0, d1n = 0.0, d2p = 0.0, d2n = 0.0;

  // Now iterate through the D type GTOs and sum their contributions
  unsigned int cIndex = set->m_cIndices[basis];
  for (unsigned int i = set->m_gtoIndices[basis];
       i < set->m_gtoIndices[basis+1]; ++i) {
    // Calculate the common factor
    double tmpGTO = exp(-set->m_gtoA[i] * dr2);
    d0  += set->m_gtoCN[cIndex++] * tmpGTO;
    d1p += set->m_gtoCN[cIndex++] * tmpGTO;
    d1n += set->m_gtoCN[cIndex++] * tmpGTO;
    d2p += set->m_gtoCN[cIndex++] * tmpGTO;
    d2n += set->m_gtoCN[cIndex++] * tmpGTO;
  }

  // Calculate the prefactors
  double xx = delta.x() * delta.x();
  double yy = delta.y() * delta.y();
  double zz = delta.z() * delta.z();
  double xy = delta.x() * delta.y();
  double xz = delta.x() * delta.z();
  double yz = delta.y() * delta.z();

  // Save values to the matrix
  int baseIndex = set->m_moIndices[basis];
  out.coeffRef(baseIndex  , 0) = (zz - dr2) * d0;
  out.coeffRef(baseIndex+1, 0) = xz * d1p;
  out.coeffRef(baseIndex+2, 0) = yz * d1n;
  out.coeffRef(baseIndex+3, 0) = (xx - yy) * d2p;
  out.coeffRef(baseIndex+4, 0) = xy * d2n;
}

unsigned int GaussianSet::numMOs()
{
  // Return the total number of MOs
  return static_cast<unsigned int>(m_moMatrix.rows());
}

unsigned int GaussianSet::numAlphaMOs()
{
  // Return the total number of MOs
  return static_cast<unsigned int>(m_alphaMoMatrix.rows());
}

unsigned int GaussianSet::numBetaMOs()
{
  // Return the total number of MOs
  return static_cast<unsigned int>(m_betaMoMatrix.rows());
}

bool GaussianSet::generateDensity()
{
  if (m_scfType == Unknown)
    return false;

  m_density.resize(m_numMOs, m_numMOs);
  m_density=Eigen::MatrixXd::Zero(m_numMOs, m_numMOs);
  for (unsigned int iBasis=0; iBasis < m_numMOs; ++iBasis) {
    for (unsigned int jBasis=0;jBasis<=iBasis; ++jBasis) {
      switch (m_scfType) {
      case rhf:
        for (unsigned int iMO = 0; iMO < m_electrons / 2; ++iMO) {
          double icoeff = m_moMatrix(iBasis, iMO);
          double jcoeff = m_moMatrix(jBasis, iMO);
          m_density(jBasis, iBasis) += 2.0 * icoeff * jcoeff;
          m_density(iBasis, jBasis) = m_density(jBasis, iBasis);
        }
        qDebug() << iBasis << ", " << jBasis << ": " << m_density(iBasis, jBasis);
        break;
      case uhf:
        for (unsigned int iaMO = 0; iaMO < m_electronsAlpha; ++iaMO) {
          double icoeff = m_alphaMoMatrix(iBasis, iaMO);
          double jcoeff = m_alphaMoMatrix(jBasis, iaMO);
          m_density(jBasis, iBasis) += icoeff * jcoeff;
          m_density(iBasis, jBasis) = m_density(jBasis, iBasis);
        }
        for (unsigned int ibMO=0;ibMO < m_electronsBeta; ibMO++) {
          double icoeff = m_betaMoMatrix(iBasis,ibMO);
          double jcoeff = m_betaMoMatrix(jBasis,ibMO);
          m_density(jBasis,iBasis) += icoeff*jcoeff;
          m_density(iBasis,jBasis) = m_density(jBasis,iBasis);
        }
        qDebug() << iBasis << ", " << jBasis << ": " << m_density(iBasis, jBasis);
        break;
      default:
        qDebug() << "Unhandled scf type:" << m_scfType;
      }
    }
  }
  return true;
}

bool GaussianSet::generateSpinDensity()
{
  if (m_scfType != uhf)
    return false;

  m_spinDensity.resize(m_numMOs, m_numMOs);
  m_spinDensity=Eigen::MatrixXd::Zero(m_numMOs, m_numMOs);
  for (unsigned int iBasis = 0; iBasis < m_numMOs; ++iBasis) {
    for (unsigned int jBasis = 0; jBasis <= iBasis; ++jBasis) {
      for (unsigned int iaMO = 0; iaMO < m_electronsAlpha; ++iaMO) {
        double icoeff = m_alphaMoMatrix(iBasis, iaMO);
        double jcoeff = m_alphaMoMatrix(jBasis ,iaMO);
        m_spinDensity(jBasis, iBasis) += icoeff * jcoeff;
        m_spinDensity(iBasis, jBasis) = m_spinDensity(jBasis, iBasis);
      }
      for (unsigned int ibMO = 0; ibMO < m_electronsBeta; ++ibMO) {
        double icoeff = m_betaMoMatrix(iBasis, ibMO);
        double jcoeff = m_betaMoMatrix(jBasis, ibMO);
        m_spinDensity(jBasis, iBasis) -= icoeff * jcoeff;
        m_spinDensity(iBasis, jBasis) = m_spinDensity(jBasis, iBasis);
      }
      qDebug() << iBasis << ", " << jBasis << ": " << m_spinDensity(iBasis, jBasis);
    }
  }
  return true;
}

void GaussianSet::outputAll()
{
  // Can be called to print out a summary of the basis set as read in
  m_numAtoms = static_cast<unsigned int>(m_molecule.atomCount());
  qDebug() << "\nGaussian Basis Set\nNumber of atoms:" << m_numAtoms;
  switch (m_scfType) {
  case rhf:
    qDebug() << "RHF orbitals";
    break;
  case uhf:
    qDebug() << "UHF orbitals";
    break;
  case rohf:
    qDebug() << "ROHF orbitals";
    break;
  default:
    qDebug() << "Uknown orbitals";
    break;
  }

  initCalculation();

  if (!isValid()) {
    qDebug() << "Basis set is marked as invalid.";
    return;
  }

  for (size_t i = 0; i < m_symmetry.size(); ++i) {
    qDebug() << i
             << "\tAtom Index:" << m_atomIndices[i]
             << "\tSymmetry:" << m_symmetry[i]
             << "\tMO Index:" << m_moIndices[i]
             << "\tGTO Index:" << m_gtoIndices[i];
  }
  qDebug() << "Symmetry:" << m_symmetry.size()
           << "\tgtoIndices:" << m_gtoIndices.size()
           << "\tLast gtoIndex:" << m_gtoIndices[m_symmetry.size()]
           << "\ngto size:" << m_gtoA.size() << m_gtoC.size() << m_gtoCN.size();
  for (size_t i = 0; i < m_symmetry.size(); ++i) {
    switch (m_symmetry[i]) {
    case S:
      qDebug() << "Shell" << i << "\tS\n  MO 1\t"
               << m_moMatrix(0, m_moIndices[i])
               << m_moMatrix(m_moIndices[i], 0);
      break;
    case P:
      qDebug() << "Shell" << i << "\tP\n  MO 1\t"
               << m_moMatrix(0, m_moIndices[i])
               << "\t" << m_moMatrix(0, m_moIndices[i] + 1)
               << "\t" << m_moMatrix(0, m_moIndices[i] + 2);
      break;
    case D:
      qDebug() << "Shell" << i << "\tD\n  MO 1\t"
               << m_moMatrix(0, m_moIndices[i])
               << "\t" << m_moMatrix(0, m_moIndices[i] + 1)
               << "\t" << m_moMatrix(0, m_moIndices[i] + 2)
               << "\t" << m_moMatrix(0, m_moIndices[i] + 3)
               << "\t" << m_moMatrix(0, m_moIndices[i] + 4)
               << "\t" << m_moMatrix(0, m_moIndices[i] + 5);
      break;
    case D5:
      qDebug() << "Shell" << i << "\tD5\n  MO 1\t"
               << m_moMatrix(0, m_moIndices[i])
               << "\t" << m_moMatrix(0, m_moIndices[i] + 1)
               << "\t" << m_moMatrix(0, m_moIndices[i] + 2)
               << "\t" << m_moMatrix(0, m_moIndices[i] + 3)
               << "\t" << m_moMatrix(0, m_moIndices[i] + 4);
      break;
    case F:
      std::cout << "Shell " << i << "\tF\n  MO 1";
      for (short j = 0; j < 10; ++j)
        std::cout << "\t" << m_moMatrix(0, m_moIndices[i] + j);
      std::cout << std::endl;
      break;
    case F7:
      std::cout << "Shell " << i << "\tF7\n  MO 1";
      for (short j = 0; j < 7; ++j)
        std::cout << "\t" << m_moMatrix(0, m_moIndices[i] + j);
      std::cout << std::endl;
      break;
    default:
      qDebug() << "Error: unhandled type...";
    }
    unsigned int cIndex = m_gtoIndices[i];
    for (size_t j = m_gtoIndices[i]; j < m_gtoIndices[i+1]; ++j) {
      if (j >= m_gtoA.size()) {
        qDebug() << "Error, j is too large!" << j << m_gtoA.size();
        continue;
      }
      qDebug() << cIndex
               << "\tc:" << m_gtoC[cIndex]
               << "\ta:" << m_gtoA[cIndex];
      ++cIndex;
    }
  }
  qDebug() << "\nEnd of orbital data...\n";
}

void GaussianSet::outputAlphaAll()
{
  // Can be called to print out a summary of the basis set as read in
  m_numAtoms = static_cast<unsigned int>(m_molecule.atomCount());
  qDebug() << "\nGaussian Basis Set\nNumber of atoms:" << m_numAtoms;
  switch (m_scfType) {
  case rhf:
    qDebug() << "RHF orbitals";
    break;
  case uhf:
    qDebug() << "UHF orbitals";
    break;
  case rohf:
    qDebug() << "ROHF orbitals";
    break;
  default:
    qDebug() << "Uknown orbitals";
    break;
  }

  initCalculation();

  if (!isValid()) {
    qDebug() << "Basis set is marked as invalid.";
    return;
  }

  for (size_t i = 0; i < m_symmetry.size(); ++i) {
    qDebug() << i
             << "\tAtom Index:" << m_atomIndices[i]
             << "\tSymmetry:" << m_symmetry[i]
             << "\tMO Index:" << m_moIndices[i]
             << "\tGTO Index:" << m_gtoIndices[i];
  }
  qDebug() << "Symmetry:" << m_symmetry.size()
           << "\tgtoIndices:" << m_gtoIndices.size()
           << "\tLast gtoIndex:" << m_gtoIndices[m_symmetry.size()]
           << "\ngto size:" << m_gtoA.size() << m_gtoC.size() << m_gtoCN.size();
  for (size_t i = 0; i < m_symmetry.size(); ++i) {
    switch (m_symmetry[i]) {
    case S:
      qDebug() << "Shell" << i << "\tS\n  MO 1\t"
               << m_alphaMoMatrix(0, m_moIndices[i])
               << m_alphaMoMatrix(m_moIndices[i], 0);
      break;
    case P:
      qDebug() << "Shell" << i << "\tP\n  MO 1\t"
               << m_alphaMoMatrix(0, m_moIndices[i])
               << "\t" << m_alphaMoMatrix(0, m_moIndices[i] + 1)
               << "\t" << m_alphaMoMatrix(0, m_moIndices[i] + 2);
      break;
    case D:
      qDebug() << "Shell" << i << "\tD\n  MO 1\t"
               << m_alphaMoMatrix(0, m_moIndices[i])
               << "\t" << m_alphaMoMatrix(0, m_moIndices[i] + 1)
               << "\t" << m_alphaMoMatrix(0, m_moIndices[i] + 2)
               << "\t" << m_alphaMoMatrix(0, m_moIndices[i] + 3)
               << "\t" << m_alphaMoMatrix(0, m_moIndices[i] + 4)
               << "\t" << m_alphaMoMatrix(0, m_moIndices[i] + 5);
      break;
    case D5:
      qDebug() << "Shell" << i << "\tD5\n  MO 1\t"
               << m_alphaMoMatrix(0, m_moIndices[i])
               << "\t" << m_alphaMoMatrix(0, m_moIndices[i] + 1)
               << "\t" << m_alphaMoMatrix(0, m_moIndices[i] + 2)
               << "\t" << m_alphaMoMatrix(0, m_moIndices[i] + 3)
               << "\t" << m_alphaMoMatrix(0, m_moIndices[i] + 4);
      break;
    case F:
      std::cout << "Shell " << i << "\tF\n  MO 1";
      for (short j = 0; j < 10; ++j)
        std::cout << "\t" << m_alphaMoMatrix(0, m_moIndices[i] + j);
      std::cout << std::endl;
      break;
    case F7:
      std::cout << "Shell " << i << "\tF7\n  MO 1";
      for (short j = 0; j < 7; ++j)
        std::cout << "\t" << m_alphaMoMatrix(0, m_moIndices[i] + j);
      std::cout << std::endl;
      break;
    default:
      qDebug() << "Error: unhandled type...";
    }
    unsigned int cIndex = m_gtoIndices[i];
    for (size_t j = m_gtoIndices[i]; j < m_gtoIndices[i+1]; ++j) {
      if (j >= m_gtoA.size()) {
        qDebug() << "Error, j is too large!" << j << m_gtoA.size();
        continue;
      }
      qDebug() << cIndex
               << "\tc:" << m_gtoC[cIndex]
               << "\ta:" << m_gtoA[cIndex];
      ++cIndex;
    }
  }
  qDebug() << "\nEnd of orbital data...\n";
}

void GaussianSet::outputBetaAll()
{
  // Can be called to print out a summary of the basis set as read in
  m_numAtoms = static_cast<unsigned int>(m_molecule.atomCount());
  qDebug() << "\nGaussian Basis Set\nNumber of atoms:" << m_numAtoms;
  switch (m_scfType) {
  case rhf:
    qDebug() << "RHF orbitals";
    break;
  case uhf:
    qDebug() << "UHF orbitals";
    break;
  case rohf:
    qDebug() << "ROHF orbitals";
    break;
  default:
    qDebug() << "Uknown orbitals";
    break;
  }

  initCalculation();

  if (!isValid()) {
    qDebug() << "Basis set is marked as invalid.";
    return;
  }

  for (size_t i = 0; i < m_symmetry.size(); ++i) {
    qDebug() << i
             << "\tAtom Index:" << m_atomIndices[i]
             << "\tSymmetry:" << m_symmetry[i]
             << "\tMO Index:" << m_moIndices[i]
             << "\tGTO Index:" << m_gtoIndices[i];
  }
  qDebug() << "Symmetry:" << m_symmetry.size()
           << "\tgtoIndices:" << m_gtoIndices.size()
           << "\tLast gtoIndex:" << m_gtoIndices[m_symmetry.size()]
           << "\ngto size:" << m_gtoA.size() << m_gtoC.size() << m_gtoCN.size();
  for (size_t i = 0; i < m_symmetry.size(); ++i) {
    switch (m_symmetry[i]) {
    case S:
      qDebug() << "Shell" << i << "\tS\n  MO 1\t"
               << m_betaMoMatrix(0, m_moIndices[i])
               << m_betaMoMatrix(m_moIndices[i], 0);
      break;
    case P:
      qDebug() << "Shell" << i << "\tP\n  MO 1\t"
               << m_betaMoMatrix(0, m_moIndices[i])
               << "\t" << m_betaMoMatrix(0, m_moIndices[i] + 1)
               << "\t" << m_betaMoMatrix(0, m_moIndices[i] + 2);
      break;
    case D:
      qDebug() << "Shell" << i << "\tD\n  MO 1\t"
               << m_betaMoMatrix(0, m_moIndices[i])
               << "\t" << m_betaMoMatrix(0, m_moIndices[i] + 1)
               << "\t" << m_betaMoMatrix(0, m_moIndices[i] + 2)
               << "\t" << m_betaMoMatrix(0, m_moIndices[i] + 3)
               << "\t" << m_betaMoMatrix(0, m_moIndices[i] + 4)
               << "\t" << m_betaMoMatrix(0, m_moIndices[i] + 5);
      break;
    case D5:
      qDebug() << "Shell" << i << "\tD5\n  MO 1\t"
               << m_betaMoMatrix(0, m_moIndices[i])
               << "\t" << m_betaMoMatrix(0, m_moIndices[i] + 1)
               << "\t" << m_betaMoMatrix(0, m_moIndices[i] + 2)
               << "\t" << m_betaMoMatrix(0, m_moIndices[i] + 3)
               << "\t" << m_betaMoMatrix(0, m_moIndices[i] + 4);
      break;
    case F:
      std::cout << "Shell " << i << "\tF\n  MO 1";
      for (short j = 0; j < 10; ++j)
        std::cout << "\t" << m_betaMoMatrix(0, m_moIndices[i] + j);
      std::cout << std::endl;
      break;
    case F7:
      std::cout << "Shell " << i << "\tF7\n  MO 1";
      for (short j = 0; j < 7; ++j)
        std::cout << "\t" << m_betaMoMatrix(0, m_moIndices[i] + j);
      std::cout << std::endl;
      break;
    default:
      qDebug() << "Error: unhandled type...";
    }
    unsigned int cIndex = m_gtoIndices[i];
    for (size_t j = m_gtoIndices[i]; j < m_gtoIndices[i+1]; ++j) {
      if (j >= m_gtoA.size()) {
        qDebug() << "Error, j is too large!" << j << m_gtoA.size();
        continue;
      }
      qDebug() << cIndex
               << "\tc:" << m_gtoC[cIndex]
               << "\ta:" << m_gtoA[cIndex];
      ++cIndex;
    }
  }
  qDebug() << "\nEnd of orbital data...\n";
}

} // End namespace Quantum
} // End namespace Avogadro
