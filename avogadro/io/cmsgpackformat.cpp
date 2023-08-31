/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cmsgpackformat.h"

#include <iostream>

using namespace std;

namespace Avogadro::Io {

CMsgPackFormat::CMsgPackFormat(): CjsonFormat()
{
  m_json = false;
}

CMsgPackFormat::~CMsgPackFormat() = default;

vector<std::string> CMsgPackFormat::fileExtensions() const
{
  vector<std::string> ext;
  ext.emplace_back("cmpk");
  return ext;
}

vector<std::string> CMsgPackFormat::mimeTypes() const
{
  vector<std::string> mime;
  mime.emplace_back("chemical/x-cmpack");
  return mime;
}

  bool CMsgPackFormat::read(std::istream& in, Core::Molecule& molecule)
  {
    return CjsonFormat::deserialize(in, molecule, false);
  }

  bool CMsgPackFormat::write(std::ostream& out, const Core::Molecule& molecule)
  {
    std::cerr << "CMsgPackFormat::write" << std::endl;
    return CjsonFormat::serialize(out, molecule, false);
  }

} // namespace Avogadro::Io
