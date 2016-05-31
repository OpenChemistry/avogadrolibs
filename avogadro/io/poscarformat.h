/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_IO_POSCARFORMAT_H
#define AVOGADRO_IO_POSCARFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Io {

/**
 * @class PoscarFormat poscarformat.h <avogadro/io/poscarformat.h>
 * @brief Implementation of the generic POSCAR format.
 * @author Patrick S. Avery
 */

class AVOGADROIO_EXPORT PoscarFormat : public FileFormat
{
public:
  PoscarFormat();
  ~PoscarFormat() AVO_OVERRIDE;

  Operations supportedOperations() const AVO_OVERRIDE
  {
    return ReadWrite | File | Stream | String;
  }

  FileFormat * newInstance() const AVO_OVERRIDE { return new PoscarFormat; }
  std::string identifier() const AVO_OVERRIDE { return "Avogadro: POSCAR"; }
  std::string name() const AVO_OVERRIDE { return "POSCAR"; }
  std::string description() const AVO_OVERRIDE
  {
    return "Format used by VASP that contains crystal cell and atom info.";
  }

  std::string specificationUrl() const AVO_OVERRIDE
  {
    return "http://cms.mpi.univie.ac.at/vasp/guide/node59.html";
  }

  std::vector<std::string> fileExtensions() const AVO_OVERRIDE;
  std::vector<std::string> mimeTypes() const AVO_OVERRIDE;

  bool read(std::istream &inStream, Core::Molecule &mol);
  bool write(std::ostream &outStream, const Core::Molecule &mol);
};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_POSCARFORMAT_H

