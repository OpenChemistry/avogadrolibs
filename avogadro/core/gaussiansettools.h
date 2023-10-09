/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_GAUSSIANSETTOOLS_H
#define AVOGADRO_CORE_GAUSSIANSETTOOLS_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include "basisset.h"
#include "vector.h"

#include <vector>

namespace Avogadro {
namespace Core {

class Cube;
class GaussianSet;
class Molecule;

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
  ~GaussianSetTools();

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

  bool isSmall(double value) const;

  /**
   * @brief Calculate the values at this position in space. The public calculate
   * functions call this function to prepare values before multiplying by the
   * molecular orbital or density matrix elements.
   * @param position The position in space to calculate the value.
   */
  std::vector<double> calculateValues(const Vector3& position) const;

  void pointS(unsigned int index, double dr2,
              std::vector<double>& values) const;
  void pointP(unsigned int index, const Vector3& delta, double dr2,
              std::vector<double>& values) const;
  void pointD(unsigned int index, const Vector3& delta, double dr2,
              std::vector<double>& values) const;
  void pointD5(unsigned int index, const Vector3& delta, double dr2,
               std::vector<double>& values) const;
  void pointF(unsigned int index, const Vector3& delta, double dr2,
              std::vector<double>& values) const;
  void pointF7(unsigned int index, const Vector3& delta, double dr2,
               std::vector<double>& values) const;
};

} // End Core namespace
} // End Avogadro namespace

#endif // AVOGADRO_CORE_GAUSSIANSETTOOLS_H
