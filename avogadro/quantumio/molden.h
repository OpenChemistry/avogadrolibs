/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2010 Geoffrey R. Hutchison
  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_MOLDEN_H
#define AVOGADRO_QUANTUMIO_MOLDEN_H

#include "avogadroquantumioexport.h"
#include <avogadro/core/gaussianset.h>
#include <avogadro/io/fileformat.h>

#include <vector>

namespace Avogadro {
namespace QuantumIO {

class AVOGADROQUANTUMIO_EXPORT MoldenFile : public Io::FileFormat
{
public:
  MoldenFile();
  ~MoldenFile() AVO_OVERRIDE;

  Operations supportedOperations() const AVO_OVERRIDE
  {
    return Read | File | Stream | String;
  }

  FileFormat * newInstance() const AVO_OVERRIDE { return new MoldenFile; }
  std::string identifier() const AVO_OVERRIDE { return "Avogadro: Molden"; }
  std::string name() const AVO_OVERRIDE { return "Molden"; }
  std::string description() const AVO_OVERRIDE
  {
    return "Molden file format.";
  }

  std::string specificationUrl() const AVO_OVERRIDE
  {
    return "http://www.cmbi.ru.nl/molden/molden_format.html";
  }

  std::vector<std::string> fileExtensions() const AVO_OVERRIDE;
  std::vector<std::string> mimeTypes() const AVO_OVERRIDE;

  bool read(std::istream &in, Core::Molecule &molecule) AVO_OVERRIDE;
  bool write(std::ostream &, const Core::Molecule &) AVO_OVERRIDE
  {
    // Empty, as we do not write out Molden files.
    return false;
  }

private:
  void outputAll();

  void processLine(std::istream &in);
  void readAtom(const std::vector<std::string> &list);
  void load(Core::GaussianSet* basis);

  double m_coordFactor;
  int m_electrons;
  unsigned int m_numBasisFunctions;
  std::vector<int> m_aNums;
  std::vector<double> m_aPos;
  std::vector<Core::GaussianSet::orbital> m_shellTypes;
  std::vector<int> m_shellNums;
  std::vector<int> m_shelltoAtom;
  std::vector<double> m_a;
  std::vector<double> m_c;
  std::vector<double> m_csp;
  std::vector<double> m_orbitalEnergy;
  std::vector<double> m_MOcoeffs;

  enum Mode { Atoms, GTO, MO, Unrecognized };
  Mode m_mode;
};

} // End namespace
}

#endif
