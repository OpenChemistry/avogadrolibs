/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_BASISSET_H
#define AVOGADRO_CORE_BASISSET_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include <string>

namespace Avogadro {
namespace Core {

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
  BasisSet() {}

  /**
   * Destructor.
   */
  virtual ~BasisSet() {}

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
  virtual unsigned int molecularOrbitalCount(ElectronType type = Paired) = 0;

  /**
   * Check if the given MO number is the HOMO or not.
   * @param n The MO number.
   * @return True if the given MO number is the HOMO.
   */
  bool homo(unsigned int n) { return n == homo(); }

  /**
   * @return The molecular orbital number corresponding to the HOMO orbital.
   */
  unsigned int homo() const { return m_electrons[0] / 2; }

  /**
   * Check if the given MO number is the LUMO or not.
   * @param n The MO number.
   * @return True if the given MO number is the LUMO.
   */
  bool lumo(unsigned int n) { return n == lumo(); }
  /**
   * @return The molecular orbital number corresponding to the LUMO orbital.
   */
  unsigned int lumo() const { return m_electrons[0] / 2 + 1; }

  /**
   * @return True of the basis set is valid, false otherwise.
   * Default is true, if false then the basis set is likely unusable.
   */
  virtual bool isValid() = 0;

protected:
  /**
   * Total number of electrons, 0 is alpha electrons and 1 is beta electrons.
   * For closed shell calculations alpha is doubly occupied and there are no
   * beta electrons.
   */
  unsigned int m_electrons[2];

  /**
   * The Molecule holds the atoms (and possibly bonds) read in from the output
   * file. Most basis sets have orbitals around these atoms, but this is not
   * necessarily the case.
   */
  Molecule* m_molecule;

  /**
   * The name of the basis set, this is usually a string identifier referencing
   * a standard basis set when only one is used.
   */
  std::string m_name;

  /**
   * The name of the theory used for the calculation.
   */
  std::string m_theoryName;
};

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

} // End namesapce Core
} // End namespace Avogadro

#endif
