/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cmsgpackformat.h"

using namespace std;

namespace Avogadro::Io {

CMsgPackFormat::CMsgPackFormat() = default;

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

} // namespace Avogadro::Io
