/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "mdcrdformat.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <iomanip>
#include <iostream>
#include <istream>
#include <ostream>
#include <sstream>
#include <string>

using std::endl;
using std::getline;
using std::map;
using std::string;
using std::to_string;
using std::vector;

namespace Avogadro {
namespace Io {

using Core::Array;
using Core::Atom;
using Core::Elements;
using Core::lexicalCast;
using Core::Molecule;
using Core::split;
using Core::trimmed;
using Core::UnitCell;

#ifndef _WIN32
using std::isalpha;
#endif

#define MDCRD_EOF -1

MdcrdFormat::MdcrdFormat() {}

MdcrdFormat::~MdcrdFormat() {}

bool MdcrdFormat::read(std::istream& inStream, Core::Molecule& mol)
{
  string title;
  float x, y, z;

  typedef map<string, unsigned char> AtomTypeMap;
  AtomTypeMap atomTypes;

  Array<Vector3> positions;

  getline(inStream, title);
  mol.setData("name", title);

  while (inStream >> x >> y >> z) {
    Vector3 pos(x, y, z);
    positions.push_back(pos);
  }

  mol.setCoordinate3d(positions, 0);
  return true;
}

bool MdcrdFormat::write(std::ostream& outStream, const Core::Molecule& mol)
{
  return false;
}

std::vector<std::string> MdcrdFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("mdcrd");
  return ext;
}

std::vector<std::string> MdcrdFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("N/A");
  return mime;
}

} // namespace Io
} // namespace Avogadro