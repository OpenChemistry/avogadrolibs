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

  SmilesWriter writer = m_writer;

  // Every option is type checked before it is read: json::value() throws when
  // the stored type does not match, and this code must not throw.
  bool valid = true;
  const auto boolOption = [&](const char* name, bool& out) {
    if (!opts.contains(name))
      return;
    if (!opts[name].is_boolean()) {
      appendError(std::string("The \"") + name +
                  "\" option must be a boolean.");
      valid = false;
      return;
    }
    out = opts[name].get<bool>();
  };

  bool atomMaps = writer.atomMaps();
  bool aromatic = writer.aromatic();
  boolOption("atomMaps", atomMaps);
  boolOption("aromatic", aromatic);
  if (!valid)
    return false;
  writer.setAtomMaps(atomMaps);
  writer.setAromatic(aromatic);

  if (opts.contains("hydrogens")) {
    if (!opts["hydrogens"].is_string()) {
      appendError("The \"hydrogens\" option must be a string.");
      return false;
    }
    const std::string hydrogens = opts["hydrogens"].get<std::string>();
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
