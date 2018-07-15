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

#ifndef AVOGADRO_IO_CJSONFORMAT_H
#define AVOGADRO_IO_CJSONFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Core {
class GaussianSet;
}
namespace Io {

/**
 * @class CjsonFormat cjsonformat.h <avogadro/io/cjsonformat.h>
 * @brief Implementation of the Chemical JSON format.
 */

class AVOGADROIO_EXPORT CjsonFormat : public FileFormat
{
public:
  CjsonFormat();
  ~CjsonFormat() override;

  Operations supportedOperations() const override
  {
    return ReadWrite | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new CjsonFormat; }
  std::string identifier() const override { return "Avogadro: CJSON"; }
  std::string name() const override { return "Chemical JSON"; }
  std::string description() const override
  {
    return "CJSON format is a lightweight intermediate format used to exchange "
           "information between Avogadro and other data parsing applications";
  }

  std::string specificationUrl() const override
  {
    return "http://wiki.openchemistry.org/Chemical_JSON";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream& out, const Core::Molecule& molecule) override;
};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_CJSONFORMAT_H
