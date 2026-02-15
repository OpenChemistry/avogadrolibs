/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_GROMACSFORMAT_H
#define AVOGADRO_IO_GROMACSFORMAT_H

#include "avogadroioexport.h"
#include "fileformat.h"

#include <avogadro/core/avogadrocore.h>

namespace Avogadro::Io {

/**
 * @class GromacsFormat gromacsformat.h <avogadro/io/gromacsformat.h>
 * @brief Simple GROMACS .gro file reader.
 */
class AVOGADROIO_EXPORT GromacsFormat : public FileFormat
{
public:
  GromacsFormat() = default;
  ~GromacsFormat() override = default;

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
    return "https://manual.gromacs.org/current/reference-manual/"
           "file-formats.html#gro";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  [[nodiscard]] bool read(std::istream& in, Core::Molecule& molecule) override;

  // Unimplemented
  [[nodiscard]] bool write(std::ostream& out,
                           const Core::Molecule& molecule) override;
};

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_GROMACSFORMAT_H
