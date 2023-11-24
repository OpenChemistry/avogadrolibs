/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_GROMACSFORMAT_H
#define AVOGADRO_IO_GROMACSFORMAT_H

#include "avogadroioexport.h"
#include "fileformat.h"

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
  ~GromacsFormat() override;

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new GromacsFormat; }
  std::string identifier() const override { return "Avogadro: GROMACS"; }
  std::string name() const override { return "GROMACS"; }
  std::string description() const override
  {
    return "Read GROMACS .gro files.";
  }

  std::string specificationUrl() const override
  {
    return "http://www.gromacs.org/Documentation/File_Formats/.gro_File";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream& out, const Core::Molecule& molecule) override;
};

} // namespace Io
} // namespace Avogadro

#endif // AVOGADRO_IO_GROMACSFORMAT_H
