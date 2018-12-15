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

#ifndef AVOGADRO_IO_VASPFORMAT_H
#define AVOGADRO_IO_VASPFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Io {

/**
 * @class PoscarFormat vaspformat.h <avogadro/io/vaspformat.h>
 * @brief Implementation of the generic POSCAR format.
 * @author Patrick S. Avery
 */

class AVOGADROIO_EXPORT PoscarFormat : public FileFormat
{
public:
  PoscarFormat();
  ~PoscarFormat() override;

  Operations supportedOperations() const override
  {
    return ReadWrite | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new PoscarFormat; }
  std::string identifier() const override { return "Avogadro: POSCAR"; }
  std::string name() const override { return "POSCAR"; }
  std::string description() const override
  {
    return "Format used by VASP that contains crystal cell and atom info.";
  }

  std::string specificationUrl() const override
  {
    return "http://cms.mpi.univie.ac.at/vasp/guide/node59.html";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& inStream, Core::Molecule& mol) override;
  bool write(std::ostream& outStream, const Core::Molecule& mol) override;
};

class AVOGADROIO_EXPORT OutcarFormat : public FileFormat
{
public:
  OutcarFormat();
  ~OutcarFormat() override;

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new OutcarFormat; }
  std::string identifier() const override { return "Avogadro: OUTCAR"; }
  std::string name() const override { return "OUTCAR"; }
  std::string description() const override
  {
    return "Format used by VASP that contains trajectory output of a DFT/MD "
           "calculation.";
  }

  std::string specificationUrl() const override
  {
    return "https://cms.mpi.univie.ac.at/wiki/index.php/OUTCAR";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& inStream, Core::Molecule& mol);
  bool write(std::ostream& outStream, const Core::Molecule& mol);
};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_VASPFORMAT_H
