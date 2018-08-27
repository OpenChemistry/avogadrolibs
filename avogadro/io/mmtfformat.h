/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_IO_MMTFFORMAT_H
#define AVOGADRO_IO_MMTFFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Core {
class GaussianSet;
}
namespace Io {

/**
 * @class MMTFFormat mmtf.h <avogadro/io/mmtf.h>
 * @brief Implementation of the MMTF format.
 */

class AVOGADROIO_EXPORT MMTFFormat : public FileFormat
{
public:
  MMTFFormat();
  ~MMTFFormat() override;

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new MMTFFormat; }
  std::string identifier() const override { return "Avogadro: MMTF"; }
  std::string name() const override { return "MacroMolecular Transmission Format"; }
  std::string description() const override
  {
    return "MMTF is a format used to express MacroMolecular data in a compressed "
           "binary format.";
  }

  std::string specificationUrl() const override
  {
    return "http://mmtf.rcsb.org/";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream& out, const Core::Molecule& molecule) override;
};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_MMTFFORMAT_H
