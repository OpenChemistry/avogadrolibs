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

#include "gromacsformat.h"

#include <avogadro/core/avogadrocore.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>

#include <string>
#include <utility>

using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Core::UnitCell;
using Avogadro::Core::lexicalCast;
using Avogadro::Core::trimmed;
using Avogadro::Core::split;

namespace Avogadro {
namespace Io {

GromacsFormat::GromacsFormat()
{
}

GromacsFormat::~GromacsFormat()
{
}

std::vector<std::string> GromacsFormat::fileExtensions() const
{
  return std::vector<std::string>(1, std::string("gro"));
}

std::vector<std::string> GromacsFormat::mimeTypes() const
{
  return std::vector<std::string>(1, std::string("chemical/x-gro"));
}

bool GromacsFormat::read(std::istream &in, Molecule &molecule)
{
  std::string buffer;
  std::string value;

  // Title
  std::getline(in, buffer);
  if (!buffer.empty())
    molecule.setData("name", trimmed(buffer));

  // Atom count
  std::getline(in, buffer);
  buffer = trimmed(buffer);
  bool ok;
  size_t numAtoms = lexicalCast<size_t>(buffer, ok);
  if (buffer.empty() || !ok) {
    appendError("Number of atoms (line 2) invalid.");
    return false;
  }

  // read atom info:
  typedef std::map<std::string, unsigned char> AtomTypeMap;
  AtomTypeMap atomTypes;
  unsigned char customElementCounter = CustomElementMin;
  Vector3 pos;
  while (numAtoms-- > 0) {
    std::getline(in, buffer);
    if (buffer.size() < 44) {
      appendError("Error reading atom specification -- line too short: "
                  + buffer);
      return false;
    }

    // Format of buffer is: (all indices start at 1)
    // Offset:  0 format: %5i   value: Residue number
    // Offset:  5 format: %-5s  value: Residue name
    // Offset: 10 format: %5s   value: Atom name
    // Offset: 15 format: %5i   value: Atom number
    // Offset: 20 format: %8.3f value: x coordinate (nm)
    // Offset: 28 format: %8.3f value: y coordinate (nm)
    // Offset: 36 format: %8.3f value: z coordinate (nm)
    // Offset: 44 format: %8.4f value: x velocity (nm/ps, a.k.a. km/s)
    // Offset: 52 format: %8.4f value: y velocity (nm/ps, a.k.a. km/s)
    // Offset: 60 format: %8.4f value: z velocity (nm/ps, a.k.a. km/s)

    // Atom name:
    value = trimmed(buffer.substr(10, 5));
    AtomTypeMap::const_iterator it = atomTypes.find(value);
    if (it == atomTypes.end()) {
      atomTypes.insert(std::make_pair(value, customElementCounter++));
      it = atomTypes.find(value);
      if (customElementCounter > CustomElementMax) {
        appendError("Custom element type limit exceeded.");
        return false;
      }
    }
    Atom atom = molecule.addAtom(it->second);

    // Coords
    for (int i = 0; i < 3; ++i) {
      value = trimmed(buffer.substr(20 + i * 8, 8));
      pos[i] = lexicalCast<Real>(value, ok);
      if (!ok || value.empty()) {
        appendError("Error reading atom specification -- invalid coordinate: '"
                    + buffer + "' (bad coord: '" + value + "')");
        return false;
      }
    }
    atom.setPosition3d(pos * static_cast<Real>(10.0)); // nm --> Angstrom
  }

  // Box description:
  // v1(x) v2(y) v3(z) [v1(y) v1(z) v2(x) v2(z) v3(x) v3(y)]
  // The last six values may be omitted, set all non-specified values to 0.
  // v1(y) == v1(z) == v2(z) == 0 always.
  std::getline(in, buffer);
  std::vector<std::string> tokens(split(buffer, ' ', true));
  if (tokens.size() > 0) {
    if (tokens.size() != 3 && tokens.size() != 9) {
      appendError("Invalid box specification -- need either 3 or 9 values: '"
                  + buffer + "'");
      return false;
    }

    // Index arrays for parsing loop:
    const int rows[] = {0, 1, 2, 1, 2, 0, 2, 0, 1};
    const int cols[] = {0, 1, 2, 0, 0, 1, 1, 2, 2};

    Matrix3 cellMatrix = Matrix3::Zero();
    for (size_t i = 0; i < tokens.size(); ++i) {
      cellMatrix(rows[i], cols[i]) = lexicalCast<Real>(tokens[i], ok);
      if (!ok || tokens[i].empty()) {
        appendError("Invalid box specification -- bad value: '"
                    + tokens[i] + "'");
        return false;
      }
    }

    UnitCell *cell = new UnitCell;
    cell->setCellMatrix(cellMatrix * static_cast<Real>(10)); // nm --> Angstrom
    molecule.setUnitCell(cell);
  }

  return true;
}

bool GromacsFormat::write(std::ostream &, const Core::Molecule &)
{
  return false;
}

} // namespace Io
} // namespace Avogadro
