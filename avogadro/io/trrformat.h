/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_TRRFORMAT_H
#define AVOGADRO_IO_TRRFORMAT_H

#include "fileformat.h"

namespace Avogadro::Io {

/**
 * @class TrrFormat trrformat.h <avogadro/io/trrformat.h>
 * @brief Implementation of the generic trr trajectory format.
 * @author Adarsh B
 */

class AVOGADROIO_EXPORT TrrFormat : public FileFormat
{
public:
  TrrFormat() = default;
  ~TrrFormat() override = default;

  Operations supportedOperations() const override
  {
    return Read | MultiMolecule | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new TrrFormat; }
  std::string identifier() const override { return "Avogadro: GROMACS TRR"; }
  std::string name() const override { return "TRR"; }
  std::string description() const override
  {
    return "Generic TRR Trajectory format.";
  }

  std::string specificationUrl() const override
  {
    return "https://manual.gromacs.org/current/reference-manual/"
           "file-formats.html#trr";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  [[nodiscard]] bool read(std::istream& inStream,
                          Core::Molecule& molecule) override;

  // uninplemented
  [[nodiscard]] bool write(std::ostream& outStream,
                           const Core::Molecule& molecule) override;
};

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_TRRFORMAT_H
