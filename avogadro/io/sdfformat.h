/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_SDFFORMAT_H
#define AVOGADRO_IO_SDFFORMAT_H

#include "fileformat.h"
#include "mdlformat.h"

namespace Avogadro {
namespace Io {

/**
 * @class SdfFormat sdfformat.h <avogadro/io/sdfformat.h>
 * @brief Implementation of the generic SDF format.
 * @author Marcus D. Hanwell
 *
 * Differs from the MDL / Mol format in that it includes properties
 *
 * Currently just supports V2000 of the format.
 */

class AVOGADROIO_EXPORT SdfFormat : public MdlFormat
{
public:
  SdfFormat();
  ~SdfFormat() override;

  Operations supportedOperations() const override
  {
    return ReadWrite | MultiMolecule | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new SdfFormat; }
  std::string identifier() const override { return "Avogadro: SDF"; }
  std::string name() const override { return "SDF"; }
  std::string description() const override
  {
    return "Generic format that contains atoms, bonds, positions.";
  }

  std::string specificationUrl() const override
  {
    return "https://web.archive.org/web/20210219065450/https://"
           "discover.3ds.com/sites/default/files/2020-08/"
           "biovia_ctfileformats_2020.pdf";
    /* for previous (2011) version, see:
    https://web.archive.org/web/20180329184712/http://download.accelrys.com/freeware/ctfile-formats/ctfile-formats.zip
    */
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  [[nodiscard]] bool read(std::istream& in, Core::Molecule& molecule) override;
  [[nodiscard]] bool write(std::ostream& out,
                           const Core::Molecule& molecule) override;
};

} // namespace Io
} // namespace Avogadro

#endif // AVOGADRO_IO_MDLFORMAT_H
