/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_BASISSET_H
#define AVOGADRO_CORE_BASISSET_H

#include "avogadrocoreexport.h"
#include "core/variant.h"

#include <array>
#include <string>

namespace Avogadro::Core {

class Molecule;

/**
 * @class BasisSet basisset.h <avogadro/core/basisset.h>
 * @brief BasisSet contains basis set data.
 * @author Marcus D. Hanwell
 *
 * This is the base class for basis sets, and has two derived classes -
 * GaussianSet and SlaterSet. It must be populated with data, with other classes
 * capable of performing calculations on the data or writing it out.
 */

class AVOGADROCORE_EXPORT BasisSet
{
public:
  /**
   * Constructor.
   */
  BasisSet() = default;

  /**
   * Destructor.
   */
  virtual ~BasisSet() = default;

  /**
   * Clone.
   */
  virtual BasisSet* clone() const = 0;

  /**
   * @brief The ElectronType enum describes the type of electrons being set or
   * retrieved. If Paired, then Alpha and Beta cannot be set, if Alpha or Beta
   * then both must be set.
   */
  enum ElectronType
  {
    Paired,
    Alpha,
    Beta
  };

  /**
   * Set the number of electrons in the BasisSet.
   * @param n The number of electrons in the BasisSet.
   * @param type The type of the electrons (Alpha, Beta, or Paired).
   */
  virtual void setElectronCount(unsigned int n, ElectronType type = Paired);

  /**
   * @param type The type of the electrons (Alpha, Beta, or Paired).
   * @return The number of electrons in the molecule.
   */
  unsigned int electronCount(ElectronType type = Paired) const;

  /**
   * Set the molecule for the basis set.
   */
  void setMolecule(Molecule* molecule_) { m_molecule = molecule_; }

  /**
   * Get the molecule this basis set belongs to.
   */
  Molecule* molecule() { return m_molecule; }
  const Molecule* molecule() const { return m_molecule; }

  /**
   * Set the name of the basis set.
   */
  void setName(const std::string& name) { m_name = name; }

  /**
   * Get the name of the basis set.
   */
  std::string name() const { return m_name; }

  /**
   * Set the name of the basis set.
   */
  void setTheoryName(const std::string& name) { m_theoryName = name; }

  /**
   * Get the name of the basis set.
   */
  std::string theoryName() const { return m_theoryName; }

  /**
   * @return The number of molecular orbitals in the BasisSet.
   */
  virtual unsigned int molecularOrbitalCount(
    ElectronType type = Paired) const = 0;

  /**
   * @return The molecular orbital number corresponding to the HOMO orbital.
   */
  unsigned int homo(ElectronType type = Paired) const { return lumo(type) - 1; }

  /**
   * @return The molecular orbital number corresponding to the LUMO orbital.
   */
  unsigned int lumo(ElectronType type = Paired) const;

  /**
   * @return True of the basis set is valid, false otherwise.
   * Default is true, if false then the basis set is likely unusable.
   */
  virtual bool isValid() = 0;

  /**
   * @return the orbital symmetry labels (if they exist) for the MOs
   */
  std::vector<std::string> symmetryLabels(ElectronType type = Paired) const
  {
    if (type == Paired || type == Alpha)
      return m_symmetryLabels[0];
    else
      return m_symmetryLabels[1];
  }

  /**
   * Set the orbital symmetry labels (a1, t2g, etc.) for the molecular
   * orbitals
   */
  void setSymmetryLabels(const std::vector<std::string>& labels,
                         ElectronType type = Paired);

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

protected:
  /**
   * Total number of electrons, 0 is alpha electrons and 1 is beta electrons.
   * For closed shell calculations alpha is doubly occupied and there are no
   * beta electrons.
   */
  std::array<unsigned int, 2> m_electrons = {};

  /**
   * The Molecule holds the atoms (and possibly bonds) read in from the output
   * file. Most basis sets have orbitals around these atoms, but this is not
   * necessarily the case.
   */
  Molecule* m_molecule = nullptr;

  /**
   * The name of the basis set, this is usually a string identifier referencing
   * a standard basis set when only one is used.
   */
  std::string m_name;

  /**
   * The name of the theory used for the calculation.
   */
  std::string m_theoryName;

  /**
   * The orbital symmetry labels (if they exist) for the MOs
   */
  std::vector<std::string> m_symmetryLabels[2];

  /**
   * @brief This block stores energies for the molecular orbitals (same
   * convention as the molecular orbital coefficients).
   */
  std::vector<double> m_moEnergy[2];

  /**
   * @brief The occupancy of the molecular orbitals.
   */
  std::vector<unsigned char> m_moOccupancy[2];
};

inline unsigned int BasisSet::lumo(ElectronType type) const
{
  if (type == Beta) {
    // check if we have occupancy data
    if (m_moOccupancy[1].size() > 0) {
      for (unsigned int i = 0; i < m_moOccupancy[1].size(); ++i) {
        if (m_moOccupancy[1][i] == 0)
          return i;
      }
    }
  } else {
    // alpha or paired
    // check if we have occupancy data - more accurate
    if (m_moOccupancy[0].size() > 0) {
      for (unsigned int i = 0; i < m_moOccupancy[0].size(); ++i) {
        if (m_moOccupancy[0][i] == 0)
          return i;
      }
    }
  }
  // fall back to electron count
  return m_electrons[0] / 2 + 1;
}

inline void BasisSet::setElectronCount(unsigned int n, ElectronType type)
{
  switch (type) {
    case Paired:
      m_electrons[0] = n;
      m_electrons[1] = 0;
      break;
    case Alpha:
      m_electrons[0] = n;
      break;
    case Beta:
      m_electrons[1] = n;
      break;
    default:
      // Shouldn't hit this condition.
      ;
  }
}

inline unsigned int BasisSet::electronCount(ElectronType type) const
{
  switch (type) {
    case Paired:
    case Alpha:
      return m_electrons[0];
    case Beta:
      return m_electrons[1];
    default:
      // Shouldn't hit this condition.
      return 0;
  }
}

inline void BasisSet::setSymmetryLabels(const std::vector<std::string>& labels,
                                        ElectronType type)
{
  if (type == Paired || type == Alpha)
    m_symmetryLabels[0] = labels;
  else
    m_symmetryLabels[1] = labels;
}

inline void BasisSet::setMolecularOrbitalEnergy(
  const std::vector<double>& energies, ElectronType type)
{
  if (type == Beta)
    m_moEnergy[1] = energies;
  else
    m_moEnergy[0] = energies;
}

inline void BasisSet::setMolecularOrbitalOccupancy(
  const std::vector<unsigned char>& occ, ElectronType type)
{
  if (type == Beta)
    m_moOccupancy[1] = occ;
  else
    m_moOccupancy[0] = occ;
}

} // namespace Avogadro::Core

#endif
