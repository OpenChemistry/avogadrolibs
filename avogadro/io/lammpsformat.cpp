/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "lammpsformat.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

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

LammpsFormat::LammpsFormat() {}

LammpsFormat::~LammpsFormat() {}

bool LammpsFormat::read(std::istream& inStream, Core::Molecule& mol)
{
  size_t numAtoms = 0, timestep = 0, x_idx = -1, y_idx = -1, z_idx = -1,
         type_idx = -1, id_idx = -1;
  double x_min = 0, x_max = 0, y_min = 0, y_max = 0, z_min = 0, z_max = 0,
         tilt_xy = 0, tilt_xz = 0, tilt_yz = 0, scale_x = 0., scale_y = 0.,
         scale_z = 0.;

  string buffer;
  getline(inStream, buffer); // Finish the first line
  buffer = trimmed(buffer);
  if (buffer != "ITEM: TIMESTEP") {
    appendError("No timestep item found.");
    return false;
  }
  getline(inStream, buffer);
  if (!buffer.empty()) {
    timestep = lexicalCast<size_t>(buffer);
    mol.setTimeStep(timestep, 0);
  }

  getline(inStream, buffer);
  buffer = trimmed(buffer);
  if (buffer != "ITEM: NUMBER OF ATOMS") {
    appendError("No number of atoms item found.");
    return false;
  }
  getline(inStream, buffer);
  if (!buffer.empty())
    numAtoms = lexicalCast<size_t>(buffer);

  // If unit cell is triclinic, tilt factors are needed to define the supercell
  getline(inStream, buffer);
  if (buffer.find("ITEM: BOX BOUNDS xy xz yz") == 0) {
    // Read x_min, x_max, tiltfactor_xy
    getline(inStream, buffer);
    vector<string> box_bounds_x(split(buffer, ' '));
    x_min = lexicalCast<double>(box_bounds_x.at(0));
    x_max = lexicalCast<double>(box_bounds_x.at(1));
    tilt_xy = lexicalCast<double>(box_bounds_x.at(2));
    // Read y_min, y_max, tiltfactor_xz
    getline(inStream, buffer);
    vector<string> box_bounds_y(split(buffer, ' '));
    y_min = lexicalCast<double>(box_bounds_y.at(0));
    y_max = lexicalCast<double>(box_bounds_y.at(1));
    tilt_xz = lexicalCast<double>(box_bounds_y.at(2));
    getline(inStream, buffer);
    // Read z_min, z_max, tiltfactor_yz
    vector<string> box_bounds_z(split(buffer, ' '));
    z_min = lexicalCast<double>(box_bounds_z.at(0));
    z_max = lexicalCast<double>(box_bounds_z.at(1));
    tilt_yz = lexicalCast<double>(box_bounds_z.at(2));

    x_min -= std::min(std::min(std::min(tilt_xy, tilt_xz), tilt_xy + tilt_xz),
                      (double)0);
    x_max -= std::max(std::max(std::max(tilt_xy, tilt_xz), tilt_xy + tilt_xz),
                      (double)0);
    y_min -= std::min(tilt_yz, (double)0);
    y_max -= std::max(tilt_yz, (double)0);
  }

  // Else if unit cell is orthogonal, tilt factors are zero
  else if (buffer.find("ITEM: BOX BOUNDS") == 0) {
    // Read x_min, x_max
    getline(inStream, buffer);
    vector<string> box_bounds_x(split(buffer, ' '));
    x_min = lexicalCast<double>(box_bounds_x.at(0));
    x_max = lexicalCast<double>(box_bounds_x.at(1));
    // Read y_min, y_max
    getline(inStream, buffer);
    vector<string> box_bounds_y(split(buffer, ' '));
    y_min = lexicalCast<double>(box_bounds_y.at(0));
    y_max = lexicalCast<double>(box_bounds_y.at(1));
    // Read z_min, z_max
    getline(inStream, buffer);
    vector<string> box_bounds_z(split(buffer, ' '));
    z_min = lexicalCast<double>(box_bounds_z.at(0));
    z_max = lexicalCast<double>(box_bounds_z.at(1));
  }

  typedef map<string, unsigned char> AtomTypeMap;
  AtomTypeMap atomTypes;
  unsigned char customElementCounter = CustomElementMin;

  // x,y,z stand for the coordinate axes
  // s stands for scaled coordinates
  // u stands for unwrapped coordinates
  // scale_x = 0. if coordinates are cartesian and 1 if fractional (scaled)
  getline(inStream, buffer);
  vector<string> labels(split(buffer, ' '));
  for (size_t i = 0; i < labels.size(); i++) {
    if (labels[i] == "x" || labels[i] == "xu") {
      x_idx = i;
      scale_x = 0.;
    } else if (labels[i] == "xs" || labels[i] == "xsu") {
      x_idx = i;
      scale_x = 1.;
    } else if (labels[i] == "y" || labels[i] == "yu") {
      y_idx = i;
      scale_y = 0.;
    } else if (labels[i] == "ys" || labels[i] == "ysu") {
      y_idx = i;
      scale_y = 1.;
    } else if (labels[i] == "z" || labels[i] == "zu") {
      z_idx = i;
      scale_z = 0.;
    } else if (labels[i] == "zs" || labels[i] == "zsu") {
      z_idx = i;
      scale_z = 1.;
    } else if (labels[i] == "type")
      type_idx = i;
    else if (labels[i] == "id")
      id_idx = i;
  }

  // Parse atoms
  for (size_t i = 0; i < numAtoms; ++i) {
    getline(inStream, buffer);
    vector<string> tokens(split(buffer, ' '));

    if (tokens.size() < labels.size() - 2) {
      appendError("Not enough tokens in this line: " + buffer);
      return false;
    }

    unsigned char atomicNum(0);
    atomicNum = lexicalCast<short int>(tokens[type_idx - 2]);

    // If parsed coordinates are fractional, the corresponding unscaling is
    // done. Else the positions are assigned as parsed.
    Vector3 pos((1 - scale_x) * lexicalCast<double>(tokens[x_idx - 2]) +
                  scale_x * (x_min + (x_max - x_min) *
                                       lexicalCast<double>(tokens[x_idx - 2])),
                (1 - scale_y) * lexicalCast<double>(tokens[y_idx - 2]) +
                  scale_y * (y_min + (y_max - y_min) *
                                       lexicalCast<double>(tokens[y_idx - 2])),
                (1 - scale_z) * lexicalCast<double>(tokens[z_idx - 2]) +
                  scale_z * (z_min + (z_max - z_min) *
                                       lexicalCast<double>(tokens[z_idx - 2])));

    AtomTypeMap::const_iterator it = atomTypes.find(to_string(atomicNum));
    if (it == atomTypes.end()) {
      atomTypes.insert(
        std::make_pair(to_string(atomicNum), customElementCounter++));
      it = atomTypes.find(to_string(atomicNum));
      if (customElementCounter > CustomElementMax) {
        appendError("Custom element type limit exceeded.");
        return false;
      }
    }
    Atom newAtom = mol.addAtom(it->second);
    newAtom.setPosition3d(pos);
  }

  // Set the custom element map if needed:
  if (!atomTypes.empty()) {
    Molecule::CustomElementMap elementMap;
    for (AtomTypeMap::const_iterator it = atomTypes.begin(),
                                     itEnd = atomTypes.end();
         it != itEnd; ++it) {
      elementMap.insert(std::make_pair(it->second, it->first));
    }
    mol.setCustomElementMap(elementMap);
  }

  // Check that all atoms were handled.
  if (mol.atomCount() != numAtoms) {
    std::ostringstream errorStream;
    errorStream << "Error parsing atom at index " << mol.atomCount()
                << " (line " << 10 + mol.atomCount() << ").\n"
                << buffer;
    appendError(errorStream.str());
    return false;
  }
  mol.setCoordinate3d(mol.atomPositions3d(), 0);
  mol.setUnitCell(new UnitCell(Vector3(x_max - x_min, 0, 0),
                               Vector3(tilt_xy, y_max - y_min, 0),
                               Vector3(tilt_xz, tilt_yz, z_max - z_min)));

  // Do we have an animation?
  size_t numAtoms2;
  int coordSet = 1;
  while (getline(inStream, buffer) && trimmed(buffer) == "ITEM: TIMESTEP") {
    x_idx = -1;
    y_idx = -1;
    z_idx = -1;
    type_idx = -1;
    id_idx = -1;
    x_min = 0;
    x_max = 0;
    y_min = 0;
    y_max = 0;
    z_min = 0;
    z_max = 0;
    tilt_xy = 0;
    tilt_xz = 0;
    tilt_yz = 0;
    scale_x = 0.;
    scale_y = 0.;
    scale_z = 0.;

    getline(inStream, buffer);
    if (!buffer.empty()) {
      timestep = lexicalCast<size_t>(buffer);
      mol.setTimeStep(timestep, coordSet);
    }

    getline(inStream, buffer);
    buffer = trimmed(buffer);
    if (buffer != "ITEM: NUMBER OF ATOMS") {
      appendError("No number of atoms item found.");
      return false;
    }
    getline(inStream, buffer);
    if (!buffer.empty())
      numAtoms2 = lexicalCast<size_t>(buffer);

    if (numAtoms2 != numAtoms) {
      appendError("Number of atoms isn't constant in the trajectory.");
    }

    // If unit cell is triclinic, tilt factors are needed to define the
    // supercell
    getline(inStream, buffer);
    if (buffer.find("ITEM: BOX BOUNDS xy xz yz") == 0) {
      // Read x_min, x_max, tiltfactor_xy
      getline(inStream, buffer);
      vector<string> box_bounds_x(split(buffer, ' '));
      x_min = lexicalCast<double>(box_bounds_x.at(0));
      x_max = lexicalCast<double>(box_bounds_x.at(1));
      tilt_xy = lexicalCast<double>(box_bounds_x.at(2));
      // Read y_min, y_max, tiltfactor_xz
      getline(inStream, buffer);
      vector<string> box_bounds_y(split(buffer, ' '));
      y_min = lexicalCast<double>(box_bounds_y.at(0));
      y_max = lexicalCast<double>(box_bounds_y.at(1));
      tilt_xz = lexicalCast<double>(box_bounds_y.at(2));
      getline(inStream, buffer);
      // Read z_min, z_max, tiltfactor_yz
      vector<string> box_bounds_z(split(buffer, ' '));
      z_min = lexicalCast<double>(box_bounds_z.at(0));
      z_max = lexicalCast<double>(box_bounds_z.at(1));
      tilt_yz = lexicalCast<double>(box_bounds_z.at(2));

      x_min -= std::min(std::min(std::min(tilt_xy, tilt_xz), tilt_xy + tilt_xz),
                        (double)0);
      x_max -= std::max(std::max(std::max(tilt_xy, tilt_xz), tilt_xy + tilt_xz),
                        (double)0);
      y_min -= std::min(tilt_yz, (double)0);
      y_max -= std::max(tilt_yz, (double)0);
    }

    // Else if unit cell is orthogonal, tilt factors are zero
    else if (buffer.find("ITEM: BOX BOUNDS") == 0) {
      // Read x_min, x_max
      getline(inStream, buffer);
      vector<string> box_bounds_x(split(buffer, ' '));
      x_min = lexicalCast<double>(box_bounds_x.at(0));
      x_max = lexicalCast<double>(box_bounds_x.at(1));
      // Read y_min, y_max
      getline(inStream, buffer);
      vector<string> box_bounds_y(split(buffer, ' '));
      y_min = lexicalCast<double>(box_bounds_y.at(0));
      y_max = lexicalCast<double>(box_bounds_y.at(1));
      // Read z_min, z_max
      getline(inStream, buffer);
      vector<string> box_bounds_z(split(buffer, ' '));
      z_min = lexicalCast<double>(box_bounds_z.at(0));
      z_max = lexicalCast<double>(box_bounds_z.at(1));
    }

    // x,y,z stand for the coordinate axes
    // s stands for scaled coordinates
    // u stands for unwrapped coordinates
    // scale_x = 0. if coordinates are cartesian and 1 if fractional (scaled)
    getline(inStream, buffer);
    labels = vector<string>(split(buffer, ' '));
    for (size_t i = 0; i < labels.size(); ++i) {
      if (labels[i] == "x" || labels[i] == "xu") {
        x_idx = i;
        scale_x = 0.;
      } else if (labels[i] == "xs" || labels[i] == "xsu") {
        x_idx = i;
        scale_x = 1.;
      } else if (labels[i] == "y" || labels[i] == "yu") {
        y_idx = i;
        scale_y = 0.;
      } else if (labels[i] == "ys" || labels[i] == "ysu") {
        y_idx = i;
        scale_y = 1.;
      } else if (labels[i] == "z" || labels[i] == "zu") {
        z_idx = i;
        scale_z = 0.;
      } else if (labels[i] == "zs" || labels[i] == "zsu") {
        z_idx = i;
        scale_z = 1.;
      } else if (labels[i] == "type")
        type_idx = i;
      else if (labels[i] == "id")
        id_idx = i;
    }

    Array<Vector3> positions;
    positions.reserve(numAtoms);

    for (size_t i = 0; i < numAtoms; ++i) {
      getline(inStream, buffer);
      vector<string> tokens(split(buffer, ' '));
      if (tokens.size() < 5) {
        appendError("Not enough tokens in this line: " + buffer);
        return false;
      }
      // If parsed coordinates are fractional, the corresponding unscaling is
      // done. Else the positions are assigned as parsed.
      Vector3 pos(
        (1 - scale_x) * lexicalCast<double>(tokens[x_idx - 2]) +
          scale_x *
            (x_min + (x_max - x_min) * lexicalCast<double>(tokens[x_idx - 2])),
        (1 - scale_y) * lexicalCast<double>(tokens[y_idx - 2]) +
          scale_y *
            (y_min + (y_max - y_min) * lexicalCast<double>(tokens[y_idx - 2])),
        (1 - scale_z) * lexicalCast<double>(tokens[z_idx - 2]) +
          scale_z *
            (z_min + (z_max - z_min) * lexicalCast<double>(tokens[z_idx - 2])));
      positions.push_back(pos);
    }

    mol.setCoordinate3d(positions, coordSet++);
    mol.setUnitCell(new UnitCell(Vector3(x_max - x_min, 0, 0),
                                 Vector3(tilt_xy, y_max - y_min, 0),
                                 Vector3(tilt_xz, tilt_yz, z_max - z_min)));
  }

  return true;
}

bool LammpsFormat::write(std::ostream& outStream, const Core::Molecule& mol)
{
  return false;
}

std::vector<std::string> LammpsFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("dump");
  return ext;
}

std::vector<std::string> LammpsFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("text/lammps");
  return mime;
}

} // end Io namespace
} // end Avogadro namespace
