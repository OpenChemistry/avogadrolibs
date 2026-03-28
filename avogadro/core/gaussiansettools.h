/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_GAUSSIANSETTOOLS_H
#define AVOGADRO_CORE_GAUSSIANSETTOOLS_H

#include "avogadrocoreexport.h"

#include "basisset.h"
#include "gaussianset.h"
#include "vector.h"

#include <vector>

namespace Avogadro::Core {

class Cube;
class Molecule;

/**
 * @brief Pre-packed shell metadata for fast evaluation.
 * Concentrates all per-shell data from GaussianSet into a single contiguous
 * struct, eliminating repeated indirect lookups into separate vectors during
 * the hot evaluation loop.
 */
struct ShellInfo
{
  int type;               //! Shell type enum (GaussianSet::S, P, D, etc.)
  int L;                  //! Angular momentum (0=S, 1=P, 2=D, ...)
  unsigned int atomIndex; //! Index into atom positions
  unsigned int moIndex;   //! Starting row in MO matrix for this shell
  unsigned int gtoStart;  //! First primitive index in exponent/coeff arrays
  unsigned int gtoEnd;    //! One-past-last primitive index
  unsigned int cStart;    //! First index into normalized coefficient array
  int nComponents;        //! Number of basis functions in this shell
  double cutoffSquared;   //! Precomputed cutoff distance squared
  double centerBohr[3];   //! Shell center in Bohr (precomputed)
};

/**
 * @class GaussianSetTools gaussiansettools.h <avogadro/core/gaussiansettools.h>
 * @brief Provide tools to calculate molecular orbitals, electron densities and
 * other derived data stored in a GaussianSet result.
 * @author Marcus D. Hanwell
 */

class AVOGADROCORE_EXPORT GaussianSetTools
{
public:
  explicit GaussianSetTools(Molecule* mol = nullptr);
  ~GaussianSetTools() = default;

  /**
   * @brief Set the electron type, must be called once MOs are available
   * @param type The electron type - Alpha, Beta, or Paired (default).
   */
  void setElectronType(BasisSet::ElectronType type) { m_type = type; }

  /**
   * @brief Populate the cube with values for the molecular orbital.
   * @param cube The cube to be populated with values.
   * @param molecularOrbitalNumber The molecular orbital number.
   * @return True on success, false on failure.
   */
  bool calculateMolecularOrbital(Cube& cube, int molecularOrbitalNumber) const;

  /**
   * @brief Calculate the value of the specified molecular orbital at the
   * position specified.
   * @param position The position in space to calculate the value.
   * @param molecularOrbitalNumber The molecular orbital number.
   * @return The value of the molecular orbital at the position specified.
   */
  double calculateMolecularOrbital(const Vector3& position,
                                   int molecularOrbitalNumber) const;

  /**
   * @brief Populate the cube with values for the electron density.
   * @param cube The cube to be populated with values.
   * @return True on success, false on failure.
   */
  bool calculateElectronDensity(Cube& cube) const;

  /**
   * @brief Calculate the value of the electron density at the position
   * specified.
   * @param position The position in space to calculate the value.
   * @return The value of the electron density at the position specified.
   */
  double calculateElectronDensity(const Vector3& position) const;

  /**
   * @brief Populate the cube with values for the spin density.
   * @param cube The cube to be populated with values.
   * @return True on success, false on failure.
   */
  bool calculateSpinDensity(Cube& cube) const;

  /**
   * @brief Calculate the value of the electron spin density at the position
   * specified.
   * @param position The position in space to calculate the value.
   * @return The value of the spin density at the position specified.
   */
  double calculateSpinDensity(const Vector3& position) const;

  /**
   * @brief Check that the basis set is valid and can be used.
   * @return True if valid, false otherwise.
   */
  bool isValid() const;

private:
  Molecule* m_molecule;
  GaussianSet* m_basis;
  BasisSet::ElectronType m_type = BasisSet::Paired;

  // Pre-packed shell data built once in the constructor
  std::vector<ShellInfo> m_shells;
  // Local contiguous copies of exponents and normalized coefficients
  std::vector<double> m_gtoA;
  std::vector<double> m_gtoCN;

  // Build m_shells and local coefficient copies from GaussianSet
  void buildShellData();

  // Calculate cutoff distance for a single shell
  double calculateShellCutoff(const ShellInfo& shell) const;

  // Shell-major grid evaluation with factored exp() and range-clipped cutoffs
  bool calculateMolecularOrbitalGrid(Cube& cube, int moNumber) const;

  // Density via occupied MO summation: ρ = Σ occ_i |ψ_i|²
  bool calculateElectronDensityGrid(Cube& cube) const;

  // Evaluate a single MO onto a double-precision grid buffer using the
  // shell-major factored-exp approach with range clipping.
  void evaluateMOGrid(int moIndex, const MatrixX& moMat, const Vector3& minBohr,
                      const Vector3& spBohr, const std::vector<double>& gridX,
                      const std::vector<double>& gridY,
                      const std::vector<double>& gridZ, int nx, int ny, int nz,
                      double* output) const;

  /**
   * @brief Calculate the values at this position in space. The public calculate
   * functions call this function to prepare values before multiplying by the
   * molecular orbital or density matrix elements.
   * @param position The position in space to calculate the value.
   * @param values Output vector to store basis function values (will be resized
   * and zeroed).
   */
  void calculateValues(const Vector3& position, Eigen::VectorXd& values) const;

  void pointS(const ShellInfo& shell, double dr2,
              Eigen::VectorXd& values) const;
  void pointP(const ShellInfo& shell, const Vector3& delta, double dr2,
              Eigen::VectorXd& values) const;
  void pointD(const ShellInfo& shell, const Vector3& delta, double dr2,
              Eigen::VectorXd& values) const;
  void pointD5(const ShellInfo& shell, const Vector3& delta, double dr2,
               Eigen::VectorXd& values) const;
  void pointF(const ShellInfo& shell, const Vector3& delta, double dr2,
              Eigen::VectorXd& values) const;
  void pointF7(const ShellInfo& shell, const Vector3& delta, double dr2,
               Eigen::VectorXd& values) const;
  void pointG(const ShellInfo& shell, const Vector3& delta, double dr2,
              Eigen::VectorXd& values) const;
  void pointG9(const ShellInfo& shell, const Vector3& delta, double dr2,
               Eigen::VectorXd& values) const;

  // Map from shell type enum to angular momentum
  // S, SP, P, D, D5, F, F7, G, G9, H, H11, I, I13
  static constexpr int symToL[13] = { 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6 };

  // Map from shell type enum to number of basis function components
  static constexpr int symToNComp[13] = { 1,  4, 3,  6,  5,  10, 7,
                                          15, 9, 21, 11, 28, 13 };
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_GAUSSIANSETTOOLS_H
