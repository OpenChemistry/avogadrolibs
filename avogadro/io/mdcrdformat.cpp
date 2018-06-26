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

#include <QtWidgets/QInputDialog>

#include <iomanip>
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

  inStream.seekg(0, inStream.end);
  int fileLen = inStream.tellg();
  inStream.seekg(0, inStream.beg);

  bool ok;
  int natoms = QInputDialog::getInt(NULL, "Prompt", "Number of atoms:", 1, 1,
                                    INT_MAX, 1, &ok);
  if (!ok) {
    appendError("Number of atoms not inputted.");
    return false;
  }

  QStringList items;
  items << "Yes"
        << "No";

  QString item = QInputDialog::getItem(
    NULL, "Prompt", "Does trajectory contain box coordinates?", items, 0, false,
    &ok);

  if (!ok) {
    appendError("Box coordinate boolean not inputted.");
    return false;
  }

  typedef map<string, unsigned char> AtomTypeMap;
  AtomTypeMap atomTypes;
  unsigned char customElementCounter = CustomElementMin;
  int coordSet = 0;

  Array<Vector3> positions;
  positions.reserve(natoms);

  getline(inStream, title);
  mol.setData("name", title);

  while ((static_cast<int>(inStream.tellg()) != fileLen) &&
         (static_cast<int>(inStream.tellg()) != MDCRD_EOF)) {
    for (int i = 0; i < natoms; ++i) {
      inStream >> x >> y >> z;
      if (coordSet == 0) {
        Vector3 pos(x, y, z);

        AtomTypeMap::const_iterator it;
        atomTypes.insert(std::make_pair(to_string(i), customElementCounter++));
        it = atomTypes.find(to_string(i));
        // if (customElementCounter > CustomElementMax) {
        //   appendError("Custom element type limit exceeded.");
        //   return false;
        // }
        Atom newAtom = mol.addAtom(it->second);
        newAtom.setPosition3d(pos);
      } else {
        Vector3 pos(x, y, z);
        positions.push_back(pos);
      }
    }

    if (coordSet == 0) {
      // Set the custom element map if needed
      if (!atomTypes.empty()) {
        Molecule::CustomElementMap elementMap;
        for (AtomTypeMap::const_iterator it = atomTypes.begin(),
                                         itEnd = atomTypes.end();
             it != itEnd; ++it) {
          elementMap.insert(std::make_pair(it->second, "Atom " + it->first));
        }
        mol.setCustomElementMap(elementMap);
      }
      mol.setCoordinate3d(mol.atomPositions3d(), coordSet++);
    } else {
      mol.setCoordinate3d(positions, coordSet++);
      positions.clear();
    }

    if (item.toStdString() == "Yes") {
      inStream >> x >> y >> z;
      mol.setUnitCell(
        new UnitCell(Vector3(x, 0, 0), Vector3(0, y, 0), Vector3(0, 0, z)));
    }
  }
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

} // end Io namespace
} // end Avogadro namespace
