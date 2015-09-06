/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_NWCHEMLOG_H
#define AVOGADRO_QUANTUMIO_NWCHEMLOG_H

#include "avogadroquantumioexport.h"
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/array.h>
#include <avogadro/io/fileformat.h>

#include <vector>

namespace Avogadro {
namespace QuantumIO {

class AVOGADROQUANTUMIO_EXPORT NWChemLog : public Io::FileFormat
{
public:
  NWChemLog();
  ~NWChemLog() AVO_OVERRIDE;
  void outputAll();

  Operations supportedOperations() const AVO_OVERRIDE
  {
    return Read | File | Stream | String;
  }

  FileFormat * newInstance() const AVO_OVERRIDE { return new NWChemLog; }
  std::string identifier() const AVO_OVERRIDE { return "Avogadro: NWChem"; }
  std::string name() const AVO_OVERRIDE { return "NWChem Log"; }
  std::string description() const AVO_OVERRIDE
  {
    return "NWChem log file format.";
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
    // Empty, as we do not write out NWChem log files.
    return false;
  }

private:
  void processLine(std::istream &in, Core::Molecule &mol);

  // Read the atoms, and their geometry.
  void readAtoms(std::istream &in, Core::Molecule &mol);

  // Read the projected frequencies.
  void readFrequencies(const std::string &line, std::istream &in,
                       Core::Molecule &mol);

  Core::Array<double> m_frequencies;
  Core::Array< Core::Array<Vector3> > m_Lx;
};

} // End namespace QuantumIO
} // End namespace Avogadro

#endif
