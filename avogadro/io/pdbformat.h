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

#ifndef AVOGADRO_IO_PDBFORMAT_H
#define AVOGADRO_IO_PDBFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Io {

/**
 * @class PdbFormat pdbformat.h <avogadro/io/pdbformat.h>
 * @brief Parser for the PDB format.
 * @author Tanuj Kumar
 */

class AVOGADROIO_EXPORT PdbFormat : public FileFormat
{
public:
  PdbFormat();
  ~PdbFormat() override;

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String; //Unsure of what all should be there
  }

  FileFormat* newInstance() const override { return new PdbFormat; }
  std::string identifier() const override { return "Avogadro: PDB"; }
  std::string name() const override { return "PDB"; }
  std::string description() const override
  {
    return "Generic format that contains atoms, bonds, positions."; //To be updated, copied from mdlformat.h
  }

  std::string specificationUrl() const override
  {
    return "http://www.wwpdb.org/documentation/file-format-content/"
           "format33/v3.3.html";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream& out, const Core::Molecule& molecule) override
  {
    // Writing a PDB file is not currently supported
    return false;
  }
};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_PDBFORMAT_H