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

#ifndef AVOGADRO_QUANTUM_GAUSSIANSET_H
#define AVOGADRO_QUANTUM_GAUSSIANSET_H

#include "basisset.h"

#include <avogadro/core/vector.h>
#include <avogadro/core/matrix.h>

#include <vector>

namespace Avogadro {
namespace Quantum {

struct GaussianShell;

/**
 * Enumeration of the Gaussian type orbitals.
 */
 enum orbital { S, SP, P, D, D5, F, F7, G, G9, H, H11, I, I13, UU };
/**
 * Enumeration of the SCF type.
 */
 enum scfType { rhf, uhf, rohf, Unknown };

 enum orbType { Alpha, Beta, Doubly };

/**
 * @class GaussianSet gaussianset.h
 * @brief GaussianSet Class
 * @author Marcus D. Hanwell
 *
 * The GaussianSet class has a transparent data structure for storing the basis
 * sets output by many quantum mechanical codes. It has a certain hierarchy
 * where shells are built up from n primitives, in this case Gaussian Type
 * Orbitals (GTOs). Each shell has a type (S, P, D, F, etc) and is composed of
 * one or more GTOs. Each GTO has a contraction coefficient, c, and an exponent,
 * a.
 *
 * When calculating Molecular Orbitals (MOs) each orthogonal shell has an
 * independent coefficient. That is the S type orbitals have one coefficient,
 * the P type orbitals have three coefficients (Px, Py and Pz), the D type
 * orbitals have five (or six if cartesian types) coefficients, and so on.
 */

class AVOGADROQUANTUM_EXPORT GaussianSet : public BasisSet
{
public:
  /**
   * Constructor.
   */
  GaussianSet();

  /**
   * Destructor.
   */
  ~GaussianSet();

  /**
   * Function to add an atom to the GaussianSet.
   * @param pos Position of the center of the QAtom.
   * @param num The atomic number of the QAtom.
   * @return The index of the added atom.
   */
  unsigned int addAtom(const Vector3& pos, int num = 0);

  /**
   * Add a basis to the basis set.
   * @param atom Index of the atom to add the Basis too.
   * @param type The type of the Basis being added.
   * @return The index of the added Basis.
   */
  unsigned int addBasis(unsigned int atom, orbital type);

  /**
   * Add a GTO to the supplied basis.
   * @param basis The index of the Basis to add the GTO to.
   * @param c The contraction coefficient of the GTO.
   * @param a The exponent of the GTO.
   * @return The index of the added GTO.
   */
  unsigned int addGTO(unsigned int basis, double c, double a);

  /**
   * Add MO coefficients to the GaussianSet.
   * @param MOs Vector containing the MO coefficients for the GaussianSet.
   */
  void addMOs(const std::vector<double>& MOs);
  void addAlphaMOs(const std::vector<double>& MOs);
  void addBetaMOs(const std::vector<double>& MOs);

  /**
   * Add an individual MO coefficient.
   * @param MO The MO coefficient.
   */
  void addMO(double MO);

  /**
   * Set the SCF density matrix for the GaussianSet.
   */
  bool setDensityMatrix(const MatrixX &m);

  /**
   * Set the spin density matrix for the GaussianSet.
   */
  bool setSpinDensityMatrix(const MatrixX &m);

  //this one builds the density matrix, provided certain information is known
  bool setDensityMatrix();

  /**
   * Debug routine, outputs all of the data in the GaussianSet.
   */
  void outputAll();
  void outputAlphaAll();
  void outputBetaAll();

  /**
   * @return The number of MOs in the GaussianSet.
   */
  unsigned int numMOs();
  /**
   * @return The number of Alpha MOs in the GaussianSet.
   */
  unsigned int numAlphaMOs();
  /**
   * @return The number of Beta MOs in the GaussianSet.
   */
  unsigned int numBetaMOs();

  /**
   * Calculate the MO over the entire range of the supplied Cube.
   * @param cube The cube to write the values of the MO into.
   * @note This function starts a threaded calculation. Use watcher()
   * to monitor progress.
   * @sa BasisSet::blockingCalculateCubeMO
   * @return True if the calculation was successful.
   */
  bool calculateCubeMO(Cube *cube, unsigned int state = 1);
  bool calculateCubeAlphaMO(Cube *cube, unsigned int state = 1);
  bool calculateCubeBetaMO(Cube *cube, unsigned int state = 1);

  /**
   * Calculate the electron density over the entire range of the supplied Cube.
   * @param cube The cube to write the values of the MO into.
   * @note This function starts a threaded calculation. Use watcher()
   * to monitor progress.
   * @sa blockingCalculateCubeDensity
   * @return True if the calculation was successful.
   */
  bool calculateCubeDensity(Cube *cube);

  /**
   * Calculate the electron spin density over the entire range of the supplied Cube.
   * @param cube The cube to write the values of the MO into.
   * @note This function starts a threaded calculation. Use watcher()
   * to monitor progress.
   * @sa blockingCalculateCubeSpinDensity
   * @return True if the calculation was successful.
   */
  bool calculateCubeSpinDensity(Cube *cube);

  /**
   * When performing a calculation the QFutureWatcher is useful if you want
   * to update a progress bar.
   */
//  QFutureWatcher<void> & watcher() { return m_watcher; }

  /**
   * Create a deep copy of @a this and return a pointer to it.
   */
  //virtual BasisSet * clone();

  //maybe there is another way this should work
  //i'm not sure about these derived classes
  scfType m_scfType;

//signals:
  /**
   * Emitted when the calculation is complete.
   */
//  void finished();

//private slots:
  /**
   * Slot to set the cube data once Qt Concurrent is done
   */
//  void calculationComplete();

private:
  // New storage of the data
  // basis set
  std::vector<int> m_symmetry;             //! Symmetry of the basis, S, P...
  std::vector<unsigned int> m_atomIndices; //! Indices into the atomPos vector
  std::vector<unsigned int> m_moIndices;   //! Indices into the MO/density matrix
  std::vector<unsigned int> m_gtoIndices;  //! Indices into the GTO vector
  std::vector<unsigned int> m_cIndices;    //! Indices into m_gtoCN
  std::vector<double> m_gtoA;              //! The GTO exponent
  std::vector<double> m_gtoC;              //! The GTO contraction coefficient
  std::vector<double> m_gtoCN;             //! The GTO contraction coefficient (normalized)
  //MO sets (first two kept for legacy code)
  MatrixX m_moMatrix;              //! MO coefficient matrix
  MatrixX m_density;               //! Density matrix
  MatrixX m_spinDensity;           //! Spin Density matrix
  MatrixX m_alphaMoMatrix;         //! up MO coefficient matrix
  MatrixX m_betaMoMatrix;          //! down MO coefficient matrix
  MatrixX m_alphaDensity;          //! up Density matrix
  MatrixX m_betaDensity;           //! down Density matrix


  unsigned int m_numMOs;         //! The number of GTOs (not always!)
  unsigned int m_numAlphaMOs;    //! The number of alpha orbitals
  unsigned int m_numBetaMOs;     //! The number of beta orbitals
  unsigned int m_numAtoms;       //! Total number of atoms in the basis set
  bool m_init;                   //! Has the calculation been initialised?
/*
  QFuture<void> m_future;
  QFutureWatcher<void> m_watcher;
  Cube *m_cube;                  //! Cube to put the results into (3D grid).
  QVector<GaussianShell> *m_gaussianShells;

  static bool isSmall(double val);

  void initCalculation();  //! Perform initialisation before any calculations
  /// Re-entrant single point forms of the calculations
  static void processPoint(GaussianShell &shell);
  static void processAlphaPoint(GaussianShell &shell);
  static void processBetaPoint(GaussianShell &shell);
  static void processDensity(GaussianShell &shell);
  static void processSpinDensity(GaussianShell &shell);
  static double pointS(GaussianSet *set, unsigned int moIndex,
                       double dr2, unsigned int indexMO, orbType type);
  static double pointP(GaussianSet *set, unsigned int moIndex,
                       const Eigen::Vector3d &delta,
                       double dr2, unsigned int indexMO, orbType type);
  static double pointD(GaussianSet *set, unsigned int moIndex,
                       const Eigen::Vector3d &delta,
                       double dr2, unsigned int indexMO, orbType type);
  static double pointD5(GaussianSet *set, unsigned int moIndex,
                        const Eigen::Vector3d &delta,
                        double dr2, unsigned int indexMO, orbType type);
  /// Calculate the basis for the density
  static void pointS(GaussianSet *set, double dr2, int basis,
                     Eigen::MatrixXd &out);
  static void pointP(GaussianSet *set, const Vector3 &delta,
                     double dr2, int basis, MatrixX &out);
  static void pointD(GaussianSet *set, const Vector3 &delta,
                     double dr2, int basis, MatrixX &out);
  static void pointD5(GaussianSet *set, const Vector3 &delta,
                      double dr2, int basis, MatrixX &out);
                      */
  bool generateDensity();
  bool generateSpinDensity();
};

} // End Quantum namespace
} // End Avogadro namespace

#endif
