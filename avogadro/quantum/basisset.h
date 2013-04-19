/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2008-2009 Marcus D. Hanwell
  Copyright 2010 David C. Lonie
  Copyright 2010-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QUANTUM_BASISSET_H
#define AVOGADRO_QUANTUM_BASISSET_H

#include "avogadroquantumexport.h"

#include <avogadro/core/molecule.h>

namespace Avogadro {

namespace QtGui {
class Cube;
}

namespace Quantum {

using QtGui::Cube;

/**
 * @class BasisSet gaussianset.h <openqube/basissetloader.h>
 * @brief BasisSet contains basis set data, calculates cubes.
 * @author Marcus D. Hanwell
 *
 * This is the base class for basis sets, and has two derived classes -
 * GaussianSet and SlaterSet. It must be populated with data, with other classes
 * capable of performing calculations on the data or writing it out.
 */

class AVOGADROQUANTUM_EXPORT BasisSet
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

  enum ElectronType {
    Electron,
    AlphaElectron,
    BetaElectron
  };

  /**
   * Set the number of electrons in the BasisSet.
   * @param n The number of electrons in the BasisSet.
   * @param type The type of the electrons (alpha, beta, doubly occupied).
   */
  virtual void setElectronCount(unsigned int n, ElectronType type = Electron);

  /**
   * @param type The type of the electrons (alpha, beta, doubly occupied).
   * @return The number of electrons in the molecule.
   */
  unsigned int electronCount(ElectronType type = Electron);

  /**
   * Set the molecule for the basis set.
   */
  void setMolecule(const Core::Molecule &molecule_) { m_molecule = molecule_; }

  /**
   * Get the molecule for the basis set.
   */
  Core::Molecule molecule() const { return m_molecule; }

  /**
   * Get a reference to the molecule.
   */
  Core::Molecule & moleculeRef() { return m_molecule; }
  const Core::Molecule & moleculeRef() const { return m_molecule; }

  /**
   * @return The number of MOs in the BasisSet.
   */
  virtual unsigned int numMOs() = 0;

  /**
   * Check if the given MO number is the HOMO or not.
   * @param n The MO number.
   * @return True if the given MO number is the HOMO.
   */
  bool HOMO(unsigned int n)
  {
    if (n + 1 == static_cast<unsigned int>(m_electrons / 2))
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
    if (n == static_cast<unsigned int>(m_electrons / 2))
      return true;
    else
      return false;
  }

  /**
   * Set the number of electrons in the BasisSet.
   * @param valid True if the basis set is valid, false otherwise.
   */
  void setIsValid(bool valid) { m_valid = valid; }

  /**
   * @return True of the basis set is valid, false otherwise.
   * Default is true, if false then the basis set is likely unusable.
   */
  bool isValid() { return m_valid; }

  /**
   * Calculate the MO over the entire range of the supplied Cube.
   * @param cube The cube to write the values of the MO into.
   * @param mo The molecular orbital number to calculate.
   * @note This function starts a threaded calculation. Use watcher() to
   * monitor progress.
   * @sa blockingCalculateCubeMO
   * @return True if the calculation was successful.
   */
  //virtual bool calculateCubeMO(Cube *cube, unsigned int mo = 1) = 0;
  //virtual bool calculateCubeAlphaMO(Cube *cube, unsigned int mo = 1) = 0;
  //virtual bool calculateCubeBetaMO(Cube *cube, unsigned int mo = 1) = 0;

  /**
   * Calculate the MO over the entire range of the supplied Cube.
   * @param cube The cube to write the values of the MO into.
   * @param mo The molecular orbital number to calculate.
   * @sa calculateCubeMO
   * @return True if the calculation was successful.
   */
  //virtual bool blockingCalculateCubeMO(Cube *cube, unsigned int mo = 1);
 // virtual bool blockingCalculateCubeAlphaMO(Cube *cube, unsigned int mo = 1);
  //virtual bool blockingCalculateCubeBetaMO(Cube *cube, unsigned int mo = 1);

  /**
   * Calculate the electron density over the entire range of the supplied Cube.
   * @param cube The cube to write the values of the MO into.
   * @note This function starts a threaded calculation. Use watcher() to
   * monitor progress.
   * @sa blockingCalculateCubeDensity
   * @return True if the calculation was successful.
   */
  //virtual bool calculateCubeDensity(Cube *cube) = 0;

  /**
   * Calculate the electron spin density over the entire range of the supplied Cube.
   * @param cube The cube to write the values of the MO into.
   * @note This function starts a threaded calculation. Use watcher() to
   * monitor progress.
   * @sa blockingCalculateCubeSpinDensity
   * @return True if the calculation was successful.
   */
  //virtual bool calculateCubeSpinDensity(Cube *cube) = 0;

  /**
   * Calculate the electron density over the entire range of the supplied Cube.
   * @param cube The cube to write the values of the MO into.
   * @sa calculateCubeDensity
   * @return True if the calculation was successful.
   */
  //virtual bool blockingCalculateCubeDensity(Cube *cube);

  /**
   * Calculate the electron spin density over the entire range of the supplied Cube.
   * @param cube The cube to write the values of the MO into.
   * @sa calculateCubeSpinDensity
   * @return True if the calculation was successful.
   */
  //virtual bool blockingCalculateCubeSpinDensity(Cube *cube);

  /**
   * Create a deep copy of @a this and return a pointer to it.
   */
  //virtual BasisSet * clone() = 0;

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
  case Electron:
    m_electrons[0] = n;
    m_electrons[1] = 0;
    break;
  case AlphaElectron:
    m_electrons[0] = n;
    break;
  case BetaElectron:
    m_electrons[1] = n;
    break;
  default:
    // Shouldn't hit this condition.
  }
}

inline unsigned int BasisSet::electronCount(ElectronType type)
{
  switch (type) {
  case Electron:
  case AlphaElectron:
    return m_electrons[0];
  case BetaElectron:
    return m_electrons[1];
  default:
    // Shouldn't hit this condition.
    return 0;
  }
}


} // End namesapce Quantum
} // End namespace Avogadro

#endif
