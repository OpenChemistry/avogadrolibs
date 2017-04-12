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

#ifndef AVOGADRO_IO_CMLFORMAT_H
#define AVOGADRO_IO_CMLFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Io {

/**
 * @class CmlFormat cmlformat.h <avogadro/io/cmlformat.h>
 * @brief Implementation of the Chemical Markup Language format.
 * @author Marcus D. Hanwell
 */

class AVOGADROIO_EXPORT CmlFormat : public FileFormat
{
public:
  CmlFormat();
  ~CmlFormat() override;

  Operations supportedOperations() const override
  {
    return ReadWrite | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new CmlFormat; }
  std::string identifier() const override { return "Avogadro: CML"; }
  std::string name() const override { return "Chemical Markup Language"; }
  std::string description() const override
  {
    return "TODO: Describe the format.";
  }

  std::string specificationUrl() const override
  {
    return "http://www.xml-cml.org/schema/schema3/";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream& out, const Core::Molecule& molecule) override;
};

} // end Io namespace
} // end Avogadro namespace

#endif // CMLFORMAT_H
