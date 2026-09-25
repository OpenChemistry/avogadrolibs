/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "smilesformat.h"

#include "smileswriter.h"

#include <string>
#include <vector>

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
  SmilesWriter writer = m_writer;

  // An option that is present but unusable is an error here rather than a
  // silent fallback, so both lookups run before either result is checked and
  // the caller hears about every bad option at once.
  bool atomMaps = writer.atomMaps();
  bool aromatic = writer.aromatic();
  bool valid = boolOption("atomMaps", atomMaps);
  valid = boolOption("aromatic", aromatic) && valid;
  if (!valid)
    return false;
  writer.setAtomMaps(atomMaps);
  writer.setAromatic(aromatic);

  std::string hydrogens;
  if (!stringOption("hydrogens", hydrogens))
    return false;
  if (!hydrogens.empty()) {
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
