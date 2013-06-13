/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2008 Marcus D. Hanwell
  Copyright 2010-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_GAMESSUS_H
#define AVOGADRO_QUANTUMIO_GAMESSUS_H

#include "avogadroquantumioexport.h"
#include <avogadro/core/gaussianset.h>
#include <avogadro/io/fileformat.h>

#include <vector>

namespace Avogadro {
namespace QuantumIO {

class AVOGADROQUANTUMIO_EXPORT GAMESSUSOutput : public Io::FileFormat
{
public:
  GAMESSUSOutput();
  ~GAMESSUSOutput() AVO_OVERRIDE;

  Operations supportedOperations() const AVO_OVERRIDE
  {
    return Read | File | Stream | String;
  }

  FileFormat * newInstance() const AVO_OVERRIDE { return new GAMESSUSOutput; }
  std::string identifier() const AVO_OVERRIDE { return "Avogadro: GAMESS"; }
  std::string name() const AVO_OVERRIDE { return "GAMESS"; }
  std::string description() const AVO_OVERRIDE
  {
    return "GAMESS US log file output parser.";
  }

  std::string specificationUrl() const AVO_OVERRIDE
  {
    return "";
  }

  std::vector<std::string> fileExtensions() const AVO_OVERRIDE;
  std::vector<std::string> mimeTypes() const AVO_OVERRIDE;

  bool read(std::istream &in, Core::Molecule &molecule) AVO_OVERRIDE;
  bool write(std::ostream &, const Core::Molecule &) AVO_OVERRIDE
  {
    // Empty, as we do not write out GAMESS log files.
    return false;
  }

private:
  /**
   * @brief Read the atom block of the log file.
   * @param in Our input stream.
   * @param molecule The molecule to add the atoms to.
   * @param angs Whether the units are Angstroms (true) or Bohr (false).
   */
  void readAtomBlock(std::istream &in, Core::Molecule &molecule, bool angs);

  /**
   * Read in the basis set block.
   */
  void readBasisSet(std::istream &in);

  /**
   * Read in the molecular orbitals.
   */
  void readEigenvectors(std::istream &in);

  /**
   * Outpull all known properties that have been read, useful for debugging.
   */
  void outputAll();

  /**
   * Load the basis with the properties read in from the file.
   */
  void load(Core::GaussianSet *basis);

  double m_coordFactor;
  int m_electrons;
  int m_electronsA;
  int m_electronsB;
  Core::ScfType m_scftype;
  unsigned int m_numBasisFunctions;
  std::vector<Core::GaussianSet::orbital> m_shellTypes;
  std::vector<int> m_shellNums;
  std::vector<int> m_shelltoAtom;
  std::vector<double> m_a;
  std::vector<double> m_c;
  std::vector<double> m_csp;
  std::vector<double> m_orbitalEnergy;
  std::vector<double> m_alphaOrbitalEnergy;
  std::vector<double> m_betaOrbitalEnergy;
  std::vector<double> m_MOcoeffs;
  std::vector<double> m_alphaMOcoeffs;
  std::vector<double> m_betaMOcoeffs;

  MatrixX m_density;     /// Total density matrix
};

}
}

#endif
