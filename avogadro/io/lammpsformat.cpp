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

#include <avogadro/core/crystaltools.h>
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
using Core::Bond;
using Core::CrystalTools;
using Core::Elements;
using Core::lexicalCast;
using Core::Molecule;
using Core::split;
using Core::trimmed;
using Core::UnitCell;

#ifndef _WIN32
using std::isalpha;
#endif

LammpsTrajectoryFormat::LammpsTrajectoryFormat() {}

LammpsTrajectoryFormat::~LammpsTrajectoryFormat() {}

bool LammpsTrajectoryFormat::read(std::istream& inStream, Core::Molecule& mol)
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

bool LammpsTrajectoryFormat::write(std::ostream& outStream,
                                   const Core::Molecule& mol)
{
  return false;
}

std::vector<std::string> LammpsTrajectoryFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("dump");
  return ext;
}

std::vector<std::string> LammpsTrajectoryFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("text/lammps");
  return mime;
}

LammpsDataFormat::LammpsDataFormat() {}

LammpsDataFormat::~LammpsDataFormat() {}

bool LammpsDataFormat::read(std::istream& inStream, Core::Molecule& mol)
{
  return false;
}

bool LammpsDataFormat::write(std::ostream& outStream, const Core::Molecule& mol)
{
  Core::Molecule mol2(mol);
  CrystalTools::rotateToStandardOrientation(mol2, CrystalTools::TransformAtoms);

  // Title
  if (mol2.data("name").toString().length())
    outStream << mol2.data("name").toString() << std::endl;
  else
    outStream << "LAMMPS data file generated by Avogadro" << std::endl;

  std::ostringstream massStream, atomStream, bondStream;
  double xmin, xmax, ymin, ymax, zmin, zmax;

  size_t numAtoms = mol2.atomCount();
  outStream << to_string(numAtoms) << " atoms\n";

  size_t numBonds = mol2.bondCount();
  outStream << to_string(numBonds) << " bonds\n";

  // A map of atomic symbols to their quantity.
  size_t idx = 1;
  Array<unsigned char> atomicNumbers = mol2.atomicNumbers();
  std::map<unsigned char, size_t> composition;
  for (Array<unsigned char>::const_iterator it = atomicNumbers.begin(),
                                            itEnd = atomicNumbers.end();
       it != itEnd; ++it) {
    if (composition.find(*it) == composition.end()) {
      composition[*it] = idx++;
    }
  }

  outStream << composition.size() << " atom types\n";

  // Masses
  massStream << "Masses\n\n";
  std::map<unsigned char, size_t>::iterator iter = composition.begin();
  while (iter != composition.end()) {
    massStream << iter->second << "   " << Elements::mass(iter->first) << "\n";
    ++iter;
  }
  massStream << std::endl << std::endl << std::endl;

  if (numAtoms) {
    // Atomic coordinates
    atomStream << "Atoms\n\n";
    for (Index i = 0; i < numAtoms; ++i) {
      Atom atom = mol2.atom(i);
      if (!atom.isValid()) {
        appendError("Internal error: Atom invalid.");
        return false;
      }
      Vector3 coords = atom.position3d();
      if (i == 0) {
        xmin = coords[0];
        xmax = coords[0];
        ymin = coords[1];
        ymax = coords[1];
        zmin = coords[2];
        zmax = coords[2];
      } else {
        xmin = std::min(coords[0], xmin);
        xmax = std::max(coords[0], xmax);
        ymin = std::min(coords[1], ymin);
        ymax = std::max(coords[1], ymax);
        zmin = std::min(coords[2], zmin);
        zmax = std::max(coords[2], zmax);
      }

      char atomline[200];
      sprintf(atomline, "%-*d %d %10f %10f %10f\n",
              static_cast<int>(log(numAtoms)) + 1, static_cast<int>(i + 1),
              static_cast<int>(composition[atomicNumbers[i]]), coords.x(),
              coords.y(), coords.z());
      atomStream << atomline;
    }

    atomStream << std::endl << std::endl;
  }

  if (numBonds) {
    // Bonds
    std::map<std::pair<unsigned char, unsigned char>, int> bondIds;
    int bondItr = 1;
    bondStream << "Bonds\n\n";
    for (Index i = 0; i < numBonds; ++i) {
      char bondline[200];
      Bond b = mol2.bond(i);
      if (bondIds.find(std::make_pair(b.atom1().atomicNumber(),
                                      b.atom2().atomicNumber())) !=
          bondIds.end()) {
        sprintf(bondline, "%-*d %7d %7d %7d\n",
                static_cast<int>(log(numAtoms) + 1), static_cast<int>(i + 1),
                bondIds[std::make_pair(b.atom1().atomicNumber(),
                                       b.atom2().atomicNumber())],
                static_cast<int>(b.atom1().index() + 1),
                static_cast<int>(b.atom2().index() + 1));
        bondStream << bondline;
      } else if (bondIds.find(std::make_pair(b.atom2().atomicNumber(),
                                             b.atom1().atomicNumber())) !=
                 bondIds.end()) {
        sprintf(bondline, "%-*d %7d %7d %7d\n",
                static_cast<int>(log(numAtoms) + 1), static_cast<int>(i + 1),
                bondIds[std::make_pair(b.atom1().atomicNumber(),
                                       b.atom2().atomicNumber())],
                static_cast<int>(b.atom2().index() + 1),
                static_cast<int>(b.atom1().index() + 1));
        bondStream << bondline;
      } else {
        bondIds.insert(std::make_pair(
          std::make_pair(b.atom1().atomicNumber(), b.atom2().atomicNumber()),
          bondItr++));
        sprintf(bondline, "%-*d %7d %7d %7d\n",
                static_cast<int>(log(numAtoms) + 1), static_cast<int>(i + 1),
                bondIds[std::make_pair(b.atom1().atomicNumber(),
                                       b.atom2().atomicNumber())],
                static_cast<int>(b.atom1().index() + 1),
                static_cast<int>(b.atom2().index() + 1));
        bondStream << bondline;
      }
    }
  }

  UnitCell* unitcell = mol2.unitCell();
  char simBoxBlock[200];
  if (unitcell) {
    const Matrix3& mat = unitcell->cellMatrix().transpose();
    sprintf(simBoxBlock,
            "%10f %10f xlo xhi\n%10f %10f ylo yhi\n%10f %10f zlo zhi\n%10f "
            "%10f %10f xy xz yz",
            0.0, mat(0, 0), 0.0, mat(1, 1), 0.0, mat(2, 2), mat(1, 0),
            mat(2, 0), mat(2, 1));
    outStream << simBoxBlock;
  } else {
    sprintf(simBoxBlock,
            "%10f %10f xlo xhi\n%10f %10f ylo yhi\n%10f %10f zlo zhi\n%10f "
            "%10f %10f xy xz yz",
            xmin - 0.5, xmax - 0.5, ymin - 0.5, ymax - 0.5, zmin - 0.5,
            zmax - 0.5, 0.0, 0.0, 0.0);
    outStream << simBoxBlock;
  }
  outStream << std::endl << std::endl << std::endl;
  outStream << massStream.str();
  outStream << atomStream.str();
  outStream << bondStream.str();

  return true;
}

std::vector<std::string> LammpsDataFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("lmpdat");
  return ext;
}

std::vector<std::string> LammpsDataFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("N/A");
  return mime;
}

} // end Io namespace
} // end Avogadro namespace
