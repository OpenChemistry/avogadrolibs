/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_CIFFORMAT_H
#define AVOGADRO_IO_CIFFORMAT_H

#include "fileformat.h"

namespace Avogadro::Io {

/**
 * @class CifFormat cifformat.h <avogadro/io/cifformat.h>
 * @brief Reader (and P1 writer) for small-molecule CIF files.
 *
 * The reader keeps the asymmetric unit of the file and records the space
 * group of the molecule (see applyCifSymmetry()); it does not fill the cell.
 * A file without fractional coordinates (a macromolecular mmCIF) or one this
 * reader cannot make sense of is handed to another reader registered for
 * "cif", normally the Open Babel plugin.
 *
 * Occupancies and displacement parameters are not stored.
 */
class AVOGADROIO_EXPORT CifFormat : public FileFormat
{
public:
  CifFormat() = default;
  ~CifFormat() override = default;

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new CifFormat; }
  std::string identifier() const override { return "Avogadro: CIF"; }
  std::string name() const override { return "CIF"; }
  std::string description() const override
  {
    return "Crystallographic Information File: unit cell, symmetry and "
           "atoms of a crystal structure.";
  }

  std::string specificationUrl() const override
  {
    return "https://www.iucr.org/resources/cif/spec";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  [[nodiscard]] bool read(std::istream& inStream,
                          Core::Molecule& molecule) override;
  [[nodiscard]] bool write(std::ostream& outStream,
                           const Core::Molecule& molecule) override;
};

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_CIFFORMAT_H
