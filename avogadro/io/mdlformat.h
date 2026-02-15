/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_MDLFORMAT_H
#define AVOGADRO_IO_MDLFORMAT_H

#include "fileformat.h"

namespace Avogadro::Io {

/**
 * @class MdlFormat mdlformat.h <avogadro/io/mdlformat.h>
 * @brief Implementation of the generic MDL format.
 * @author Marcus D. Hanwell
 *
 * Currently just supports V2000 of the format.
 */

class AVOGADROIO_EXPORT MdlFormat : public FileFormat
{
public:
  MdlFormat() = default;
  ~MdlFormat() override = default;

  Operations supportedOperations() const override
  {
    return ReadWrite | MultiMolecule | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new MdlFormat; }
  std::string identifier() const override { return "Avogadro: MDL"; }
  std::string name() const override { return "MDL"; }
  std::string description() const override
  {
    return "Generic format that contains atoms, bonds, positions.";
  }

  std::string specificationUrl() const override
  {
    return "https://web.archive.org/web/20210219065450/https://"
           "discover.3ds.com/sites/default/files/2020-08/"
           "biovia_ctfileformats_2020.pdf";
    // http://help.accelrysonline.com/ulm/onelab/1.0/content/ulm_pdfs/direct/reference/ctfileformats2016.pdf
    /* for previous (2011) version, see:
    https://web.archive.org/web/20180329184712/http://download.accelrys.com/freeware/ctfile-formats/ctfile-formats.zip
    */
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  [[nodiscard]] bool read(std::istream& in, Core::Molecule& molecule) override;
  [[nodiscard]] bool readV3000(std::istream& in, Core::Molecule& molecule);
  [[nodiscard]] bool write(std::ostream& out,
                           const Core::Molecule& molecule) override;
  [[nodiscard]] bool writeV3000(std::ostream& out,
                                const Core::Molecule& molecule);

protected:
  bool m_writeProperties = false;
  bool m_is2D = false;
};

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_MDLFORMAT_H
