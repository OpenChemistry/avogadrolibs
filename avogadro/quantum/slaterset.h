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

#ifndef AVOGADRO_QUANTUM_SLATERSET_H
#define AVOGADRO_QUANTUM_SLATERSET_H

#include "basisset.h"

#include <avogadro/core/vector.h>
#include <avogadro/core/matrix.h>

#include <QtCore/QFuture>

#include <Eigen/Dense>
#include <vector>

namespace Avogadro {
namespace Quantum {

/**
 * @class SlaterSet slaterset.h
 * @brief SlaterSet Class
 * @author Marcus D. Hanwell
 *
 * The SlaterSet class has a transparent data structure for storing the basis
 * sets output by many quantum mechanical codes. It has a certain hierarchy
 * where shells are built up from n primitives, in this case Slater Type
 * Orbitals (STOs). Each shell has a type (S, P, D, F, etc) and is composed of
 * one or more STOs. Each STO has a contraction coefficient, c, and an exponent,
 * a.
 *
 * When calculating Molecular Orbitals (MOs) each orthogonal shell has an
 * independent coefficient. That is the S type orbitals have one coefficient,
 * the P type orbitals have three coefficients (Px, Py and Pz), the D type
 * orbitals have five (or six if cartesian types) coefficients, and so on.
 */

struct SlaterShell;

class AVOGADROQUANTUM_EXPORT SlaterSet : public BasisSet
{
  Q_OBJECT

public:
  /**
   * Constructor.
   */
  SlaterSet();

  /**
   * Destructor.
   */
  ~SlaterSet();

  /**
   * Enumeration of the Slater orbital types.
   */
  enum slater { S, PX, PY, PZ, X2, XZ, Z2, YZ, XY, UU };

  /**
   * Function to add an atom to the SlaterSet.
   * @param pos Position of the center of the QAtom.
   * @return The index of the added atom.
   */
  bool addAtoms(const std::vector<Eigen::Vector3d> &pos);

  /**
   * Add a basis to the basis set.
   * @param i Index of the atom to add the Basis too.
   * @return The index of the added Basis.
   */
  bool addSlaterIndices(const std::vector<int> &i);

  /**
   * Add the symmetry types for the orbitals.
   * @param t Vector containing the types of symmetry using the slater enum.
   */
  bool addSlaterTypes(const std::vector<int> &t);

  /**
   * Add a STO to the supplied basis.
   * @param zetas The exponents of the STOs
   * @return True if successful.
   */
  bool addZetas(const std::vector<double> &zetas);

  /**
   * The PQNs for the orbitals.
   */
  bool addPQNs(const std::vector<int> &pqns);

  /**
   * The overlap matrix.
   * @param m Matrix containing the overlap matrix for the basis.
   */
  bool addOverlapMatrix(const Eigen::MatrixXd &m);

  /**
   * Add Eigen Vectors to the SlaterSet.
   * @param MOs Matrix of the eigen vectors for the SlaterSet.
   */
  bool addEigenVectors(const Eigen::MatrixXd &e);

  /**
   * Add the density matrix to the SlaterSet.
   * @param d Density matrix for the SlaterSet.
   */
  bool addDensityMatrix(const Eigen::MatrixXd &d);

  /**
   * @return The number of MOs in the BasisSet.
   */
  unsigned int numMOs();

  void outputAll();

  bool calculateCubeMO(Cube *cube, unsigned int state = 1);
  bool calculateCubeAlphaMO(Cube *cube, unsigned int state = 1);
  bool calculateCubeBetaMO(Cube *cube, unsigned int state = 1);

  bool calculateCubeDensity(Cube *cube);
  bool calculateCubeSpinDensity(Cube *cube);

  QFutureWatcher<void> & watcher() { return m_watcher; }

  /**
   * Create a deep copy of @a this and return a pointer to it.
   */
  virtual BasisSet * clone();

private Q_SLOTS:
  /**
   * Slot to set the cube data once Qt Concurrent is done
   */
  void calculationComplete();

private:
  std::vector<Eigen::Vector3d> m_atomPos;
  std::vector<int> m_slaterIndices;
  std::vector<int> m_slaterTypes;
  std::vector<double> m_zetas;
  std::vector<int> m_pqns, m_PQNs;

  std::vector<double> m_factors;
  Eigen::MatrixXd m_overlap;
  Eigen::MatrixXd m_eigenVectors;
  Eigen::MatrixXd m_density;
  Eigen::MatrixXd m_normalized;
  bool m_initialized;

  QFuture<void> m_future;
  QFutureWatcher<void> m_watcher;
  Cube *m_cube; // Cube to put the results into
  QVector<SlaterShell> m_slaterShells;

  bool initialize();

  static bool isSmall(double val);
  unsigned int factorial(unsigned int n);

  static void processPoint(SlaterShell &shell);
  static void processDensity(SlaterShell &shell);
  static double pointSlater(SlaterSet *set, const Eigen::Vector3d &delta,
                            double dr2, unsigned int slater,
                            unsigned int indexMO);
  static double pointSlater(SlaterSet *set, const Eigen::Vector3d &delta,
                            double dr2, unsigned int slater,
                            unsigned int indexMO, double expZeta);
  static double calcSlater(SlaterSet *set, const Eigen::Vector3d &delta,
                           double dr2, unsigned int slater);
};

} // End Quantum namespace
} // End Avogadro namespace

#endif
