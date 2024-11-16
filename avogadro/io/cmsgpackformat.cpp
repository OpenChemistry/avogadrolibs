/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cmsgpackformat.h"

#include <iostream>

namespace Avogadro::Io {

std::vector<std::string> CMsgPackFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.emplace_back("cmpk");
  return ext;
}

std::vector<std::string> CMsgPackFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.emplace_back("chemical/x-cmpack");
  return mime;
}

bool CMsgPackFormat::read(std::istream& in, Core::Molecule& molecule)
{
  return CjsonFormat::deserialize(in, molecule, false);
}

bool CMsgPackFormat::write(std::ostream& out, const Core::Molecule& molecule)
{
  return CjsonFormat::serialize(out, molecule, false);
}

} // namespace Avogadro::Io
