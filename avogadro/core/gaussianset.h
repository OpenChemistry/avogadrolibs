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

#ifndef AVOGADRO_CORE_GAUSSIANSET_H
#define AVOGADRO_CORE_GAUSSIANSET_H

#include "basisset.h"

#include <avogadro/core/vector.h>
#include <avogadro/core/matrix.h>

#include <vector>

namespace Avogadro {
namespace Core {

/**
 * @class GaussianSet gaussianset.h <avogadro/core/gaussianset.h>
 * @brief A container for Gaussian type outputs from QM codes.
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

class AVOGADROCORE_EXPORT GaussianSet : public BasisSet
{
public:
  /**
   * Constructor.
   */
  GaussianSet();

  /**
   * Destructor.
   */
  ~GaussianSet() AVO_OVERRIDE;

  /**
   * Enumeration of the Gaussian type orbitals.
   */
   enum orbital { S, SP, P, D, D5, F, F7, G, G9, H, H11, I, I13, UU };

  /**
   * Add a basis to the basis set.
   * @param atom Index of the atom to add the Basis to.
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
  unsigned int addGto(unsigned int basis, double c, double a);

  /**
   * Set the molecular orbital (MO) coefficients to the GaussianSet.
   * @param MOs Vector containing the MO coefficients for the GaussianSet.
   * @param type The type of the MOs (Alpha or Beta).
   */
  void setMolecularOrbitals(const std::vector<double>& MOs,
                            ElectronType type);

  /**
   * Set the SCF density matrix for the GaussianSet.
   */
  bool setDensityMatrix(const MatrixX &m);

  /**
   * Set the spin density matrix for the GaussianSet.
   */
  bool setSpinDensityMatrix(const MatrixX &m);

  /**
   * @brief Generate the density matrix if we have the required information.
   * @return True on success, false on failure.
   */
  bool generateDensityMatrix();

  /**
   * @return The number of molecular orbitals in the GaussianSet.
   */
  unsigned int molecularOrbitalCount(ElectronType type) AVO_OVERRIDE;

  /**
   * Debug routine, outputs all of the data in the GaussianSet.
   * @param The electrons to output the information for.
   */
  void outputAll(ElectronType type);

  /**
   * @return True of the basis set is valid, false otherwise.
   * Default is true, if false then the basis set is likely unusable.
   */
  bool isValid() AVO_OVERRIDE;

  /**
   * Initialize the calculation, this must normally be done before anything.
   */
  void initCalculation();

  /**
   * Accessors for the various properties of the GaussianSet.
   */
  std::vector<int>& symmetry() { return m_symmetry; }
  std::vector<unsigned int>& atomIndices() { return m_atomIndices; }
  std::vector<unsigned int>& moIndices() { return m_moIndices; }
  std::vector<unsigned int>& gtoIndices() { return m_gtoIndices; }
  std::vector<unsigned int>& cIndices() { return m_cIndices; }
  std::vector<double>& gtoA() { return m_gtoA; }
  std::vector<double>& gtoC() { return m_gtoC; }
  std::vector<double>& gtoCN() { initCalculation(); return m_gtoCN; }
  MatrixX& moMatrix() { return m_moMatrix[0]; }
  MatrixX& densityMatrix() { return m_density; }
  MatrixX& spinDensityMatrix() { return m_spinDensity; }

private:
  /**
   * @brief This group is used once, and refers to the entire molecule.
   */
  std::vector<int> m_symmetry;             //! Symmetry of the basis, S, P...
  std::vector<unsigned int> m_atomIndices; //! Indices into the atomPos vector
  std::vector<unsigned int> m_moIndices;   //! Indices into the MO/density matrix
  std::vector<unsigned int> m_gtoIndices;  //! Indices into the GTO vector
  std::vector<unsigned int> m_cIndices;    //! Indices into m_gtoCN
  std::vector<double> m_gtoA;              //! The GTO exponent
  std::vector<double> m_gtoC;              //! The GTO contraction coefficient
  std::vector<double> m_gtoCN;             //! The GTO contraction coefficient (normalized)
  /**
   * @brief This block can be once (doubly) or in two parts (alpha and beta) for
   * open shell calculations.
   */
  MatrixX m_moMatrix[2];            //! MO coefficient matrix
  MatrixX m_density;                //! Density matrix
  MatrixX m_spinDensity;            //! Spin Density matrix

  unsigned int m_numMOs;            //! The number of GTOs (not always!)
  bool m_init;                      //! Has the calculation been initialised?

  /**
   * @brief Generate the density matrix if we have the required information.
   * @return True on success, false on failure.
   */
  bool generateDensity();

  /**
   * @brief Generate the spin density matrix if we have the required information.
   * @return True on success, false on failure.
   */
  bool generateSpinDensity();
};

} // End Core namespace
} // End Avogadro namespace

#endif
