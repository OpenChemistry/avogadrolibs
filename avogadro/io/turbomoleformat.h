/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_TURBOMOLEFORMAT_H
#define AVOGADRO_IO_TURBOMOLEFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Io {

/**
 * @class TurbomoleFormat turbomoleformat.h <avogadro/io/turbomoleformat.h>
 * @brief Implementation of the Turbomole coord format.
 * @author Geoffrey Hutchison
 */

class AVOGADROIO_EXPORT TurbomoleFormat : public FileFormat
{
public:
  TurbomoleFormat();
  ~TurbomoleFormat() override;

  Operations supportedOperations() const override
  {
    return ReadWrite | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new TurbomoleFormat; }
  std::string identifier() const override { return "Avogadro: Turbomole Coord"; }
  std::string name() const override { return "Turbomole"; }
  std::string description() const override
  {
    return "Generic format that tabulates atomic symbols and 3D positions.";
  }

  std::string specificationUrl() const override
  {
    return "https://xtb-docs.readthedocs.io/en/latest/geometry.html#turbomole-coordinate-input";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& inStream, Core::Molecule& molecule) override;
  bool write(std::ostream& outStream, const Core::Molecule& molecule) override;
};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_TURBOMOLEFORMAT_H
