/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_MMTFFORMAT_H
#define AVOGADRO_IO_MMTFFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Core {
class GaussianSet;
}
namespace Io {

/**
 * @class MMTFFormat mmtfformat.h <avogadro/io/mmtfformat.h>
 * @brief Implementation of the MMTF format.
 */

class AVOGADROIO_EXPORT MMTFFormat : public FileFormat
{
public:
  MMTFFormat();
  ~MMTFFormat() override;

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new MMTFFormat; }
  std::string identifier() const override { return "Avogadro: MMTF"; }
  std::string name() const override
  {
    return "MacroMolecular Transmission Format";
  }
  std::string description() const override
  {
    return "MMTF is a format used to express MacroMolecular data in a "
           "compressed binary format.";
  }

  std::string specificationUrl() const override
  {
    return "http://mmtf.rcsb.org/";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream& out, const Core::Molecule& molecule) override;
};

} // namespace Io
} // namespace Avogadro

#endif // AVOGADRO_IO_MMTFFORMAT_H
