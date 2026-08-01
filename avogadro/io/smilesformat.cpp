/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "smilesformat.h"

#include "smileswriter.h"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using json = nlohmann::json;

namespace Avogadro::Io {

std::vector<std::string> SmilesFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.emplace_back("smi");
  ext.emplace_back("smiles");
  return ext;
}

std::vector<std::string> SmilesFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.emplace_back("chemical/x-daylight-smiles");
  return mime;
}

bool SmilesFormat::read(std::istream&, Core::Molecule&)
{
  appendError("Reading SMILES is not supported by this format.");
  return false;
}

bool SmilesFormat::write(std::ostream& outStream,
                         const Core::Molecule& molecule)
{
  // A malformed options string parses to a discarded value, on which value()
  // would throw; fall back to the typed settings instead.
  json opts = json::parse(options(), nullptr, false);
  if (!opts.is_object())
    opts = json::object();

  SmilesWriter writer;
  writer.setHydrogenMode(m_hydrogenMode);
  writer.setAtomMaps(opts.value("atomMaps", m_atomMaps));
  writer.setAromatic(opts.value("aromatic", m_aromatic));

  if (opts.contains("hydrogens")) {
    const std::string hydrogens = opts.value("hydrogens", std::string());
    if (hydrogens == "implicit")
      writer.setHydrogenMode(SmilesWriter::HydrogenMode::Implicit);
    else if (hydrogens == "bracket")
      writer.setHydrogenMode(SmilesWriter::HydrogenMode::Bracket);
    else if (hydrogens == "explicit")
      writer.setHydrogenMode(SmilesWriter::HydrogenMode::Explicit);
    else {
      appendError("Unknown value for the \"hydrogens\" option: " + hydrogens);
      return false;
    }
  }

  std::string smiles;
  if (!writer.write(molecule, smiles)) {
    appendError(writer.error());
    return false;
  }

  outStream << smiles << "\n";
  return true;
}

} // namespace Avogadro::Io
