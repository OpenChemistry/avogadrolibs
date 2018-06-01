/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_IO_DCDFORMAT_H
#define AVOGADRO_IO_DCDFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Io {

/**
 * @class DcdFormat dcdformat.h <avogadro/io/dcdformat.h>
 * @brief Implementation of the generic dcd trajectory format.
 * @author Adarsh B
 */

class AVOGADROIO_EXPORT DcdFormat : public FileFormat
{
public:
  DcdFormat();
  ~DcdFormat() override;

  Operations supportedOperations() const override
  {
    return ReadWrite | MultiMolecule | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new DcdFormat; }
  std::string identifier() const override { return "Avogadro: DCD"; }
  std::string name() const override { return "DCD"; }
  std::string description() const override
  {
    return "CHARMM/NAMD/LAMMPS DCD Trajectory format.";
  }

  std::string specificationUrl() const override { return ""; }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& inStream, Core::Molecule& molecule) override;
  bool write(std::ostream& outStream, const Core::Molecule& molecule) override;
};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_DCDFORMAT_H
