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

#ifndef AVOGADRO_CORE_BASISSET_H
#define AVOGADRO_CORE_BASISSET_H

#include <vector>

#include "avogadrocore.h"

namespace Avogadro {
namespace Core {

/**
 * Enumeration of the SCF type.
 */
enum ScfType {
  Rhf,    // All orbitals doubly occupied.
  Uhf,    // Alpha and Beta have separate orbitals and possibly different number of electrons.
  Rohf,   // Some orbitals doubly occupied and some not.
  Unknown
};

/**
 * @brief The ElectronType enum describes the type of electrons being set or
 * retrieved. Alpha and Beta both must be set regardless of shell type.
 */
enum ElectronType {
  Alpha,
  Beta
};

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
  BasisSet(): m_scfType(Unknown) {}

  /**
   * Destructor.
   */
  virtual ~BasisSet() {}

  /**
   * Set the number of electrons in the BasisSet.
   * @param n The number of electrons in the BasisSet.
   * @param type The type of the electrons (Alpha or Beta).
   */
  virtual void setElectronCount(unsigned int n, ElectronType type);

  /**
   * @param type The type of the electrons (Alpha or Beta).
   * @return The number of electrons in the molecule for the designated spin
   */
  unsigned int electronCount(ElectronType type) const;

  /**
   * Get the total electrons, alpha + beta
   * @return The total number of electrons in the molecule
   */
  unsigned int totalElectronCount() const {
    return electronCount(Alpha) + electronCount(Beta);
  }

  /**
   * Set the molecule for the basis set.
   */
  void setMolecule(Molecule *molecule_) { m_molecule = molecule_; }

  /**
   * Get the molecule this basis set belongs to.
   */
  Molecule * molecule() { return m_molecule; }
  const Molecule * molecule() const { return m_molecule; }

  /**
   * @return The number of molecular orbitals in the BasisSet.
   */
  virtual unsigned int molecularOrbitalCount(ElectronType type) = 0;

  /**
   * Check if the given MO number is the HOMO or not.
   * @param n The MO number.
   * @return True if the given MO number is the HOMO.
   */
  bool homo(unsigned int n, ElectronType type) const
  {
    return n == homo(type);
  }

  /**
   * @return The molecular orbital number corresponding to the HOMO orbital.
   */
  unsigned int homo(ElectronType type) const
  {
    switch (type) {
      case Alpha:
        return m_electrons[0];
      case Beta:
        return m_electrons[1];
      default:
        // shouldn't get here
        return 0;
    }
  }


  /**
   * Check if the given MO number is the LUMO or not.
   * @param n The MO number.
   * @return True if the given MO number is the LUMO.
   */
  bool lumo(unsigned int n, ElectronType type) const
  {
    return n == lumo(type);
  }
  /**
   * @return The molecular orbital number corresponding to the LUMO orbital.
   */
  unsigned int lumo(ElectronType type) const
  {
    return homo(type) + 1;
  }


  /**
   * @return True of the basis set is valid, false otherwise.
   * Default is true, if false then the basis set is likely unusable.
   */
  virtual bool isValid() = 0;

  /**
   * Set the orbital energies
   */
  bool setOrbitalEnergies(std::vector<double> energies, ElectronType type) {
    switch(type) {
      case Alpha:
        m_alphaMOEnergies = energies;
        break;
      case Beta:
        m_betaMOEnergies = energies;
        break;
      default:
        return false;
    }
    return true;
  }

  /**
   * Set the SCF type for the object.
   */
  void setScfType(ScfType type) { m_scfType = type; }

  /**
   * Get the SCF type for the object.
   */
  ScfType scfType() const { return m_scfType; }

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
  Molecule *m_molecule;

  /**
   * Energies of the alpha molecular orbitals
   */
  std::vector<double> m_alphaMOEnergies;

  /**
   * Energies of the beta molecular orbitals. If the system is restricted the
   * the beta energies will be unset.
   */
  std::vector<double> m_betaMOEnergies;

private:
  ScfType m_scfType;
};

inline void BasisSet::setElectronCount(unsigned int n, ElectronType type)
{
  switch (type) {
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
