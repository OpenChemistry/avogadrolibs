/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_GAUSSIANSET_H
#define AVOGADRO_CORE_GAUSSIANSET_H

#include "avogadrocoreexport.h"

#include "basisset.h"

#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>

#include <vector>

namespace Avogadro {
namespace Core {

/**
 * Enumeration of the SCF type.
 */
enum ScfType
{
  Rhf,
  Uhf,
  Rohf,
  Unknown
};

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
  ~GaussianSet() override;

  /**
   * Clone.
   */
  GaussianSet* clone() const override { return new GaussianSet(*this); }

  /**
   * Enumeration of the Gaussian type orbitals.
   */
  enum orbital
  {
    S,
    SP,
    P,
    D,
    D5,
    F,
    F7,
    G,
    G9,
    H,
    H11,
    I,
    I13,
    UU
  };

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
   * @param type The type of the MOs (Paired, Alpha, Beta).
   */
  void setMolecularOrbitals(const std::vector<double>& MOs,
                            ElectronType type = Paired);

  /**
   * Set the molecular orbital (MO) coefficients for a given index. Note
   * that this must be used with coordinate sets to work correctly.
   * @param MOs Vector containing the MO coefficients for the GaussianSet.
   * @param type The type of the MOs (Paired, Alpha, Beta).
   * @param index The index of the MO in the sequence.
   */
  void setMolecularOrbitals(const std::vector<double>& MOs, ElectronType type,
                            Index index);

  /**
   * Get the number of elements in the set.
   */
  int setCount() { return static_cast<int>(m_moMatrixSet[0].size()); }

  /**
   * Set the active element in the set, this expects a corresponding
   * coordinate set element, and will change the active MO matrix.
   */
  bool setActiveSetStep(int index);

  /**
   * @brief Set the molecular orbital energies, expected in Hartrees.
   * @param energies The vector containing energies for the MOs of type
   * @param type The type of the electrons being set.
   */
  void setMolecularOrbitalEnergy(const std::vector<double>& energies,
                                 ElectronType type = Paired);

  /**
   * @brief Set the molecular orbital occupancies.
   * @param occ The occupancies for the MOs of type.
   * @param type The type of the electrons being set.
   */
  void setMolecularOrbitalOccupancy(const std::vector<unsigned char>& occ,
                                    ElectronType type = Paired);

  /**
   * @brief This enables support of sparse orbital sets, and provides a mapping
   * from the index in memory to the actual molecular orbital number.
   * @param nums The MO numbers (starting with an index of 1 for the first one).
   * @param type The MO type (Paired, Alpha, Beta).
   */
  void setMolecularOrbitalNumber(const std::vector<unsigned int>& nums,
                                 ElectronType type = Paired);

  /**
   * Set the SCF density matrix for the GaussianSet.
   */
  bool setDensityMatrix(const MatrixX& m);

  /**
   * Set the spin density matrix for the GaussianSet.
   */
  bool setSpinDensityMatrix(const MatrixX& m);

  /**
   * @brief Generate the density matrix if we have the required information.
   * @return True on success, false on failure.
   */
  bool generateDensityMatrix();

  /**
   * @brief Generate the spin density matrix if we have the required
   * information.
   * @return True on success, false on failure.
   */
  bool generateSpinDensityMatrix();

  /**
   * @return The number of molecular orbitals in the GaussianSet.
   */
  unsigned int molecularOrbitalCount(ElectronType type = Paired) override;

  /**
   * Debug routine, outputs all of the data in the GaussianSet.
   * @param type The electrons to output the information for.
   */
  void outputAll(ElectronType type = Paired);

  /**
   * @return True of the basis set is valid, false otherwise.
   * Default is true, if false then the basis set is likely unusable.
   */
  bool isValid() override;

  /**
   * Set the SCF type for the object.
   */
  void setScfType(ScfType type) { m_scfType = type; }

  /**
   * Get the SCF type for the object.
   */
  ScfType scfType() const { return m_scfType; }

  /**
   * Set the functional name (if applicable).
   */
  void setFunctionalName(const std::string& name) { m_functionalName = name; }

  /**
   * Get the functional name (empty if none used).
   */
  std::string functionalName() const { return m_functionalName; }

  /**
   * Initialize the calculation, this must normally be done before anything.
   */
  void initCalculation();

  /**
   * Accessors for the various properties of the GaussianSet.
   */
  std::vector<int>& symmetry() { return m_symmetry; }
  std::vector<int> symmetry() const { return m_symmetry; }
  std::vector<unsigned int>& atomIndices() { return m_atomIndices; }
  std::vector<unsigned int> atomIndices() const { return m_atomIndices; }
  std::vector<unsigned int>& moIndices() { return m_moIndices; }
  std::vector<unsigned int> moIndices() const { return m_moIndices; }
  std::vector<unsigned int>& gtoIndices() { return m_gtoIndices; }
  std::vector<unsigned int> gtoIndices() const { return m_gtoIndices; }
  std::vector<unsigned int>& cIndices() { return m_cIndices; }
  std::vector<unsigned int> cIndices() const { return m_cIndices; }
  std::vector<double>& gtoA() { return m_gtoA; }
  std::vector<double> gtoA() const { return m_gtoA; }
  std::vector<double>& gtoC() { return m_gtoC; }
  std::vector<double> gtoC() const { return m_gtoC; }
  std::vector<double>& gtoCN()
  {
    initCalculation();
    return m_gtoCN;
  }

  MatrixX& moMatrix(ElectronType type = Paired)
  {
    if (type == Paired || type == Alpha)
      return m_moMatrix[0];
    else
      return m_moMatrix[1];
  }

  MatrixX moMatrix(ElectronType type = Paired) const
  {
    if (type == Paired || type == Alpha)
      return m_moMatrix[0];
    else
      return m_moMatrix[1];
  }

  std::vector<double>& moEnergy(ElectronType type = Paired)
  {
    if (type == Paired || type == Alpha)
      return m_moEnergy[0];
    else
      return m_moEnergy[1];
  }

  std::vector<double> moEnergy(ElectronType type = Paired) const
  {
    if (type == Paired || type == Alpha)
      return m_moEnergy[0];
    else
      return m_moEnergy[1];
  }

  std::vector<unsigned char>& moOccupancy(ElectronType type = Paired)
  {
    if (type == Paired || type == Alpha)
      return m_moOccupancy[0];
    else
      return m_moOccupancy[1];
  }

  std::vector<unsigned char> moOccupancy(ElectronType type = Paired) const
  {
    if (type == Paired || type == Alpha)
      return m_moOccupancy[0];
    else
      return m_moOccupancy[1];
  }

  std::vector<unsigned int>& moNumber(ElectronType type = Paired)
  {
    if (type == Paired || type == Alpha)
      return m_moNumber[0];
    else
      return m_moNumber[1];
  }

  std::vector<unsigned int> moNumber(ElectronType type = Paired) const
  {
    if (type == Paired || type == Alpha)
      return m_moNumber[0];
    else
      return m_moNumber[1];
  }

  MatrixX& densityMatrix() { return m_density; }
  MatrixX& spinDensityMatrix() { return m_spinDensity; }

private:
  /**
   * @brief This group is used once, and refers to the entire molecule.
   */
  std::vector<int> m_symmetry;             //! Symmetry of the basis, S, P...
  std::vector<unsigned int> m_atomIndices; //! Indices into the atomPos vector
  std::vector<unsigned int> m_moIndices;  //! Indices into the MO/density matrix
  std::vector<unsigned int> m_gtoIndices; //! Indices into the GTO vector
  std::vector<unsigned int> m_cIndices;   //! Indices into m_gtoCN
  std::vector<double> m_gtoA;             //! The GTO exponent
  std::vector<double> m_gtoC;             //! The GTO contraction coefficient
  std::vector<double> m_gtoCN; //! The GTO contraction coefficient (normalized)

  /**
   * @brief This block can be once (doubly) or in two parts (alpha and beta) for
   * open shell calculations.
   */
  MatrixX m_moMatrix[2]; //! MO coefficient matrix

  /**
   * @brief If there are a sequence of related MOs, they are stored here, and
   * set as the active MOs upon demand. Alpha will store Paired or the Alpha,
   * Beta will store Beta coefficients for the appropriate calculation types.
   */
  std::vector<MatrixX> m_moMatrixSet[2];

  /**
   * @brief This block stores energies for the molecular orbitals (same
   * convention as the molecular orbital coefficients).
   */
  std::vector<double> m_moEnergy[2];

  /**
   * @brief The occupancy of the molecular orbitals.
   */
  std::vector<unsigned char> m_moOccupancy[2];

  /**
   * @brief This stores the molecular orbital number (when they are sparse). It
   * is used to lookup the actual index of the molecular orbital data.
   */
  std::vector<unsigned int> m_moNumber[2];

  MatrixX m_density;     //! Density matrix
  MatrixX m_spinDensity; //! Spin Density matrix

  unsigned int m_numMOs; //! The number of GTOs (not always!)
  bool m_init;           //! Has the calculation been initialised?

  ScfType m_scfType;

  std::string m_functionalName;
};

} // namespace Core
} // namespace Avogadro

#endif
