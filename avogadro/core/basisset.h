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

#include "molecule.h"

namespace Avogadro {
namespace Core {

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
   * @brief The ElectronType enum describes the type of electrons being set or
   * retrieved. If doubly, then alpha and beta cannot be set, if alpha or beta
   * then both must be set.
   */
  enum ElectronType {
    doubly,
    alpha,
    beta
  };

  /**
   * Set the number of electrons in the BasisSet.
   * @param n The number of electrons in the BasisSet.
   * @param type The type of the electrons (alpha, beta, doubly occupied).
   */
  virtual void setElectronCount(unsigned int n, ElectronType type = doubly);

  /**
   * @param type The type of the electrons (alpha, beta, doubly occupied).
   * @return The number of electrons in the molecule.
   */
  unsigned int electronCount(ElectronType type = doubly);

  /**
   * Set the molecule for the basis set.
   */
  void setMolecule(Core::Molecule *molecule_) { m_molecule = molecule_; }

  /**
   * Get the molecule this basis set belongs to.
   */
  Core::Molecule * molecule() { return m_molecule; }
  const Core::Molecule * molecule() const { return m_molecule; }

  /**
   * @return The number of molecular orbitals in the BasisSet.
   */
  virtual unsigned int molecularOrbitalCount(ElectronType type = doubly) = 0;

  /**
   * Check if the given MO number is the HOMO or not.
   * @param n The MO number.
   * @return True if the given MO number is the HOMO.
   */
  bool HOMO(unsigned int n)
  {
    if (n + 1 == static_cast<unsigned int>(m_electrons[0] / 2))
      return true;
    else
      return false;
  }

  /**
   * Check if the given MO number is the LUMO or not.
   * @param n The MO number.
   * @return True if the given MO number is the LUMO.
   */
  bool LUMO(unsigned int n)
  {
    if (n == static_cast<unsigned int>(m_electrons[0] / 2))
      return true;
    else
      return false;
  }

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
  Core::Molecule *m_molecule;

};

inline void BasisSet::setElectronCount(unsigned int n, ElectronType type)
{
  switch (type) {
  case doubly:
    m_electrons[0] = n;
    m_electrons[1] = 0;
    break;
  case alpha:
    m_electrons[0] = n;
    break;
  case beta:
    m_electrons[1] = n;
    break;
  default:
    // Shouldn't hit this condition.
    ;
  }
}

inline unsigned int BasisSet::electronCount(ElectronType type)
{
  switch (type) {
  case doubly:
  case alpha:
    return m_electrons[0];
  case beta:
    return m_electrons[1];
  default:
    // Shouldn't hit this condition.
    return 0;
  }
}

} // End namesapce Core
} // End namespace Avogadro

#endif
