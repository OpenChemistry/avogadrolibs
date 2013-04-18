/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_IO_MDLFORMAT_H
#define AVOGADRO_IO_MDLFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Io {

/**
 * @class MdlFormat mdlformat.h <avogadro/io/mdlformat.h>
 * @brief Implementation of the generic MDL format.
 * @author Marcus D. Hanwell
 *
 * Currently just supports V2000 of the format.
 */

class AVOGADROIO_EXPORT MdlFormat : public FileFormat
{
public:
  MdlFormat();
  ~MdlFormat() AVO_OVERRIDE;

  Operations supportedOperations() const AVO_OVERRIDE
  {
    return ReadWrite | File | Stream | String;
  }

  FileFormat * newInstance() const AVO_OVERRIDE { return new MdlFormat; }
  std::string identifier() const AVO_OVERRIDE { return "Avogadro: MDL"; }
  std::string name() const AVO_OVERRIDE { return "MDL"; }
  std::string description() const AVO_OVERRIDE
  {
    return "Generic format that contains atoms, bonds, positions.";
  }

  std::string specificationUrl() const AVO_OVERRIDE
  {
    return "http://download.accelrys.com/freeware/ctfile-formats/ctfile-formats.zip";
  }

  std::vector<std::string> fileExtensions() const AVO_OVERRIDE;
  std::vector<std::string> mimeTypes() const AVO_OVERRIDE;

  bool read(std::istream &in, Core::Molecule &molecule) AVO_OVERRIDE;
  bool write(std::ostream &out, const Core::Molecule &molecule) AVO_OVERRIDE;
};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_XMLFORMAT_H
