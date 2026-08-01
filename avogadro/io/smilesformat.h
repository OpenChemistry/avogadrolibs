/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_SMILESFORMAT_H
#define AVOGADRO_IO_SMILESFORMAT_H

#include "fileformat.h"

namespace Avogadro::Io {

/**
 * @class SmilesFormat smilesformat.h <avogadro/io/smilesformat.h>
 * @brief Implementation of the SMILES line notation.
 *
 * Writing only. A SMILES string carries no coordinates, so reading one yields
 * a molecule with every atom at the origin; until Avogadro can generate
 * coordinates natively, reading stays with the Open Babel plugin and this
 * format deliberately does not advertise Read.
 *
 * Behaviour is controlled through setOptions() with a JSON object:
 * @code
 * { "hydrogens": "implicit" | "bracket" | "explicit", "atomMaps": false }
 * @endcode
 * See SmilesWriter for what those mean. Note that "atomMaps" implies
 * "explicit", and that both default to the interchange-safe values, since
 * this format's output is pasted into other programs and sent to web
 * services.
 */

class AVOGADROIO_EXPORT SmilesFormat : public FileFormat
{
public:
  SmilesFormat() = default;
  ~SmilesFormat() override = default;

  Operations supportedOperations() const override
  {
    return Write | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new SmilesFormat; }
  std::string identifier() const override { return "Avogadro: SMILES"; }
  std::string name() const override { return "SMILES"; }
  std::string description() const override
  {
    return "Line notation describing molecular connectivity.";
  }

  std::string specificationUrl() const override
  {
    return "http://opensmiles.org/opensmiles.html";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  [[nodiscard]] bool read(std::istream& inStream,
                          Core::Molecule& molecule) override;
  [[nodiscard]] bool write(std::ostream& outStream,
                           const Core::Molecule& molecule) override;
};

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_SMILESFORMAT_H
