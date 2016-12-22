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

#ifndef AVOGADRO_QUANTUMIO_NWCHEMJSON_H
#define AVOGADRO_QUANTUMIO_NWCHEMJSON_H

#include "avogadroquantumioexport.h"
#include <avogadro/io/fileformat.h>

namespace Avogadro {
namespace QuantumIO {

/**
 * @class NWChemJson nwchemjson.h <avogadro/quantumio/nwchemjson.h>
 * @brief Implementation of the NWChem JSON format.
 * @author Marcus D. Hanwell
 */

class AVOGADROQUANTUMIO_EXPORT NWChemJson : public Io::FileFormat
{
public:
  NWChemJson();
  ~NWChemJson() AVO_OVERRIDE;

  Operations supportedOperations() const AVO_OVERRIDE
  {
    return Read | File | Stream | String;
  }

  FileFormat * newInstance() const AVO_OVERRIDE { return new NWChemJson; }
  std::string identifier() const AVO_OVERRIDE { return "Avogadro: NWCHEMJSON"; }
  std::string name() const AVO_OVERRIDE { return "NWChem JSON"; }
  std::string description() const AVO_OVERRIDE
  {
    return "TODO: Describe the format.";
  }

  std::string specificationUrl() const AVO_OVERRIDE
  {
    return "";
  }

  std::vector<std::string> fileExtensions() const AVO_OVERRIDE;
  std::vector<std::string> mimeTypes() const AVO_OVERRIDE;

  bool read(std::istream &in, Core::Molecule &molecule) AVO_OVERRIDE;
  bool write(std::ostream &out, const Core::Molecule &molecule) AVO_OVERRIDE;
};

} // end QuantumIO namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_NWCHEMJSON_H
