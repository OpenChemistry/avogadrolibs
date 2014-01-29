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

#ifndef AVOGADRO_IO_GROMACSFORMAT_H
#define AVOGADRO_IO_GROMACSFORMAT_H

#include "fileformat.h"
#include "avogadroioexport.h"

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace Io {

/**
 * @class GromacsFormat gromacsformat.h <avogadro/io/gromacsformat.h>
 * @brief Simple GROMACS .gro file reader.
 */
class AVOGADROIO_EXPORT GromacsFormat : public FileFormat
{
public:
  GromacsFormat();
  ~GromacsFormat() AVO_OVERRIDE;

  Operations supportedOperations() const AVO_OVERRIDE
  {
    return Read | File | Stream | String;
  }

  FileFormat * newInstance() const AVO_OVERRIDE { return new GromacsFormat; }
  std::string identifier() const AVO_OVERRIDE { return "Avogadro: GROMACS"; }
  std::string name() const AVO_OVERRIDE { return "GROMACS"; }
  std::string description() const AVO_OVERRIDE
  {
    return "Read GROMACS .gro files.";
  }

  std::string specificationUrl() const AVO_OVERRIDE
  {
    return "http://www.gromacs.org/Documentation/File_Formats/.gro_File";
  }

  std::vector<std::string> fileExtensions() const AVO_OVERRIDE;
  std::vector<std::string> mimeTypes() const AVO_OVERRIDE;

  bool read(std::istream &in, Core::Molecule &molecule) AVO_OVERRIDE;
  bool write(std::ostream &out, const Core::Molecule &molecule) AVO_OVERRIDE;
};

} // namespace Io
} // namespace Avogadro

#endif // AVOGADRO_IO_GROMACSFORMAT_H
