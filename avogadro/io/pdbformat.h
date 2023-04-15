/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new PdbFormat; }
  std::string identifier() const override { return "Avogadro: PDB"; }
  std::string name() const override { return "PDB"; }
  std::string description() const override
  {
    return "Format that contains atoms, bonds, positions and secondary"
           "structures of proteins.";
  }

  std::string specificationUrl() const override
  {
    return "http://www.wwpdb.org/documentation/file-format-content/"
           "format33/v3.3.html";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream&, const Core::Molecule&) override
  {
    // Writing a PDB file is not currently supported
    return false;
  }

  void perceiveSubstitutedCations(Core::Molecule& molecule);
};

} // namespace Io
} // namespace Avogadro

#endif // AVOGADRO_IO_PDBFORMAT_H
