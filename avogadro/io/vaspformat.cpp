/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "vaspformat.h"

#include <avogadro/core/elements.h> // for atomicNumberFromSymbol()
#include <avogadro/core/matrix.h>   // for matrix3
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h> // for split(), trimmed(), lexicalCast()
#include <avogadro/core/vector.h>    // for Vector3

#include <algorithm> // for std::count()
#include <iomanip>
#include <iostream>

namespace Avogadro {
namespace Io {

using std::getline;
using std::map;
using std::string;
using std::vector;

using Core::Array;
using Core::Atom;
using Core::Elements;
using Core::lexicalCast;
using Core::Molecule;
using Core::split;
using Core::trimmed;
using Core::UnitCell;

PoscarFormat::PoscarFormat() {}

PoscarFormat::~PoscarFormat() {}

bool PoscarFormat::read(std::istream& inStream, Core::Molecule& mol)
{
  size_t numLines = std::count(std::istreambuf_iterator<char>(inStream),
                               std::istreambuf_iterator<char>(), '\n');

  // There must be at least 7 "\n"'s to have a minimum crystal (including 1
  // atom)
  if (numLines < 7) {
    appendError("Error: POSCAR file is 7 or fewer lines long");
    return false;
  }

  // We have to go back to the beginning if we are going to read again
  inStream.clear();
  inStream.seekg(0, std::ios::beg);

  // We'll use these throughout
  bool ok;
  string line;
  vector<string> stringSplit;

  // First line is comment line
  getline(inStream, line);
  line = trimmed(line);
  string title = " ";
  if (!line.empty())
    title = line;

  // Next line is scaling factor
  getline(inStream, line);
  double scalingFactor = lexicalCast<double>(line, ok);

  if (!ok) {
    appendError("Error: Could not convert scaling factor to double in POSCAR");
    return false;
  }

  Matrix3 cellMat;

  // Next comes the matrix
  for (size_t i = 0; i < 3; ++i) {
    getline(inStream, line);
    stringSplit = split(line, ' ');
    // If this is not three, then there is some kind of error in the line
    if (stringSplit.size() != 3) {
      appendError("Error reading lattice vectors in POSCAR");
      return false;
    }
    // UnitCell expects a matrix of this form
    cellMat(0, i) = lexicalCast<double>(stringSplit.at(0)) * scalingFactor;
    cellMat(1, i) = lexicalCast<double>(stringSplit.at(1)) * scalingFactor;
    cellMat(2, i) = lexicalCast<double>(stringSplit.at(2)) * scalingFactor;
  }

  // Sometimes, atomic symbols go here.
  getline(inStream, line);
  stringSplit = split(line, ' ');

  if (stringSplit.empty()) {
    appendError("Error reading numbers of atom types in POSCAR");
    return false;
  }

  // Try a lexical cast here. If it fails, assume we have an atomic symbols list
  lexicalCast<unsigned int>(trimmed(stringSplit.at(0)), ok);
  vector<string> symbolsList;
  vector<unsigned char> atomicNumbers;

  if (!ok) {
    // Assume atomic symbols are here and store them
    symbolsList = split(line, ' ');
    // Store atomic nums
    for (size_t i = 0; i < symbolsList.size(); ++i)
      atomicNumbers.push_back(Elements::atomicNumberFromSymbol(symbolsList[i]));
    // This next one should be atom types
    getline(inStream, line);
  }
  // If the atomic symbols aren't here, try to find them in the title
  // In Vasp 4.x, symbols are in the title like so: " O4H2 <restOfTitle>"
  else {
    stringSplit = split(title, ' ');
    if (stringSplit.size() != 0) {
      string trimmedFormula = trimmed(stringSplit.at(0));
      // Let's replace all numbers with spaces
      for (size_t i = 0; i < trimmedFormula.size(); ++i) {
        if (isdigit(trimmedFormula.at(i)))
          trimmedFormula[i] = ' ';
      }
      // Now get the symbols with a simple space split
      symbolsList = split(trimmedFormula, ' ');
      for (size_t i = 0; i < symbolsList.size(); ++i)
        atomicNumbers.push_back(
          Elements::atomicNumberFromSymbol(symbolsList.at(i)));
    }
  }

  stringSplit = split(line, ' ');
  vector<unsigned int> atomCounts;
  for (size_t i = 0; i < stringSplit.size(); ++i) {
    unsigned int atomCount = lexicalCast<unsigned int>(stringSplit.at(i));
    atomCounts.push_back(atomCount);
  }

  // If we never filled up the atomic numbers, fill them up
  // now with "1, 2, 3..."
  if (atomicNumbers.size() == 0)
    for (size_t i = 1; i <= atomCounts.size(); ++i)
      atomicNumbers.push_back(i);

  if (atomicNumbers.size() != atomCounts.size()) {
    appendError("Error: numSymbols and numTypes are not equal in POSCAR!");
    return false;
  }

  // Starts with either [Ss]elective dynamics, [KkCc]artesian, or
  // other for fractional coords.
  getline(inStream, line);
  line = trimmed(line);

  // If selective dynamics, get the next line
  if (line.empty() || line.at(0) == 'S' || line.at(0) == 's')
    getline(inStream, line);

  line = trimmed(line);
  if (line.empty()) {
    appendError("Error determining Direct or Cartesian in POSCAR");
    return false;
  }

  bool cart;
  // Check if we're using cartesian or fractional coordinates:
  if (line.at(0) == 'K' || line.at(0) == 'k' || line.at(0) == 'C' ||
      line.at(0) == 'c') {
    cart = true;
  }
  // Assume direct if one of these was not found
  else {
    cart = false;
  }

  vector<Vector3> atoms;
  for (size_t i = 0; i < atomCounts.size(); ++i) {
    for (size_t j = 0; j < atomCounts.at(i); ++j) {
      getline(inStream, line);
      stringSplit = split(line, ' ');
      // This may be greater than 3 with selective dynamics
      if (stringSplit.size() < 3) {
        appendError("Error reading atomic coordinates in POSCAR");
        return false;
      }
      Vector3 tmpAtom(lexicalCast<double>(stringSplit.at(0)),
                      lexicalCast<double>(stringSplit.at(1)),
                      lexicalCast<double>(stringSplit.at(2)));
      atoms.push_back(tmpAtom);
    }
  }

  // Let's make a unit cell
  UnitCell* cell = new UnitCell(cellMat);

  // If our atomic coordinates are fractional, convert them to Cartesian
  if (!cart) {
    for (size_t i = 0; i < atoms.size(); ++i)
      atoms[i] = cell->toCartesian(atoms.at(i));
  }
  // If they're cartesian, we just need to apply the scaling factor
  else {
    for (size_t i = 0; i < atoms.size(); ++i)
      atoms[i] *= scalingFactor;
  }

  // If we made it this far, the read was a success!
  // Delete the current molecule. Add the new title and unit cell
  mol.clearAtoms();
  mol.setData("name", title);
  mol.setUnitCell(cell);

  // Now add the atoms
  size_t k = 0;
  for (size_t i = 0; i < atomCounts.size(); ++i) {
    unsigned char atomicNum = atomicNumbers.at(i);
    for (size_t j = 0; j < atomCounts.at(i); ++j) {
      Atom newAtom = mol.addAtom(atomicNum);
      newAtom.setPosition3d(atoms.at(k));
      ++k;
    }
  }

  return true;
}

bool PoscarFormat::write(std::ostream& outStream, const Core::Molecule& mol)
{
  // Title
  if (mol.data("name").toString().length())
    outStream << mol.data("name").toString() << std::endl;
  else
    outStream << "POSCAR" << std::endl;

  // Scaling factor
  outStream << " 1.00000000" << std::endl;

  // 3x3 matrix. Transpose is needed to orient the matrix correctly.
  const Matrix3& mat = mol.unitCell()->cellMatrix().transpose();
  for (size_t i = 0; i < 3; ++i) {
    for (size_t j = 0; j < 3; ++j) {
      outStream << "   " << std::setw(10) << std::right << std::fixed
                << std::setprecision(8) << mat(i, j);
    }
    outStream << std::endl;
  }

  // Adapted from chemkit:
  // A map of atomic symbols to their quantity.
  Array<unsigned char> atomicNumbers = mol.atomicNumbers();
  std::map<unsigned char, size_t> composition;
  for (Array<unsigned char>::const_iterator it = atomicNumbers.begin(),
                                            itEnd = atomicNumbers.end();
       it != itEnd; ++it) {
    composition[*it]++;
  }

  // Atom symbols
  std::map<unsigned char, size_t>::iterator iter = composition.begin();
  while (iter != composition.end()) {
    outStream << "   " << Elements::symbol(iter->first);
    ++iter;
  }
  outStream << std::endl;

  // Numbers of each type
  iter = composition.begin();
  while (iter != composition.end()) {
    outStream << "   " << iter->second;
    ++iter;
  }
  outStream << std::endl;

  // Direct or cartesian?
  outStream << "Direct" << std::endl;

  // Final section is atomic coordinates
  size_t numAtoms = mol.atomCount();
  // We need to make sure we that group the atomic numbers together.
  // The outer loop is for grouping them.
  iter = composition.begin();
  while (iter != composition.end()) {
    unsigned char currentAtomicNum = iter->first;
    for (size_t i = 0; i < numAtoms; ++i) {
      // We need to group atomic numbers together. If this one is not
      // the current atomic number, skip over it.
      if (atomicNumbers.at(i) != currentAtomicNum)
        continue;

      Atom atom = mol.atom(i);
      if (!atom.isValid()) {
        appendError("Internal error: Atom invalid.");
        return false;
      }
      Vector3 fracCoords = mol.unitCell()->toFractional(atom.position3d());
      outStream << "  " << std::setw(10) << std::right << std::fixed
                << std::setprecision(8) << fracCoords.x() << "  "
                << std::setw(10) << std::right << std::fixed
                << std::setprecision(8) << fracCoords.y() << "  "
                << std::setw(10) << std::right << std::fixed
                << std::setprecision(8) << fracCoords.z() << "\n";
    }
    ++iter;
  }

  return true;
}

std::vector<std::string> PoscarFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("POSCAR");
  return ext;
}

std::vector<std::string> PoscarFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("N/A");
  return mime;
}

OutcarFormat::OutcarFormat() {}

OutcarFormat::~OutcarFormat() {}

bool OutcarFormat::read(std::istream& inStream, Core::Molecule& mol)
{
  std::string buffer, dashedStr, positionStr, latticeStr;
  positionStr = " POSITION";
  latticeStr = "  Lattice vectors:";
  dashedStr = " -----------";
  std::vector<std::string> stringSplit;
  int coordSet = 0, natoms = 0;
  Array<Vector3> positions;
  Vector3 ax1, ax2, ax3;
  bool ax1Set = false, ax2Set = false, ax3Set = false;

  typedef map<string, unsigned char> AtomTypeMap;
  AtomTypeMap atomTypes;
  unsigned char customElementCounter = CustomElementMin;

  while (getline(inStream, buffer)) {
    // Checks whether the buffer object contains the lattice vectors keyword
    if (strncmp(buffer.c_str(), latticeStr.c_str(), latticeStr.size()) == 0) {
      // Checks whether lattice vectors have been already set. Reason being that
      // only the first occurrence denotes the true lattice vectors, and the
      // ones following these are vectors of the primitive cell.
      if (!(ax1Set && ax2Set && ax3Set)) {
        getline(inStream, buffer);
        for (int i = 0; i < 3; ++i) {
          getline(inStream, buffer);
          stringSplit = split(buffer, ' ');
          if (stringSplit[0] == "A1") {
            ax1 = Vector3(lexicalCast<double>(stringSplit.at(3).substr(
                            0, stringSplit.at(3).size() - 1)),
                          lexicalCast<double>(stringSplit.at(4).substr(
                            0, stringSplit.at(4).size() - 1)),
                          lexicalCast<double>(stringSplit.at(5).substr(
                            0, stringSplit.at(5).size() - 1)));
            ax1Set = true;
          } else if (stringSplit[0] == "A2") {
            ax2 = Vector3(lexicalCast<double>(stringSplit.at(3).substr(
                            0, stringSplit.at(3).size() - 1)),
                          lexicalCast<double>(stringSplit.at(4).substr(
                            0, stringSplit.at(4).size() - 1)),
                          lexicalCast<double>(stringSplit.at(5).substr(
                            0, stringSplit.at(5).size() - 1)));
            ax2Set = true;
          } else if (stringSplit[0] == "A3") {
            ax3 = Vector3(lexicalCast<double>(stringSplit.at(3).substr(
                            0, stringSplit.at(3).size() - 1)),
                          lexicalCast<double>(stringSplit.at(4).substr(
                            0, stringSplit.at(4).size() - 1)),
                          lexicalCast<double>(stringSplit.at(5).substr(
                            0, stringSplit.at(5).size() - 1)));
            ax3Set = true;
          }
        }
        // Checks whether all the three axis vectors have been read
        if (ax1Set && ax2Set && ax3Set) {
          mol.setUnitCell(new UnitCell(ax1, ax2, ax3));
        }
      }
    }

    // Checks whether the buffer object contains the POSITION keyword
    else if (strncmp(buffer.c_str(), positionStr.c_str(), positionStr.size()) ==
             0) {
      getline(inStream, buffer);
      // Double checks whether the succeeding line is a sequence of dashes
      if (strncmp(buffer.c_str(), dashedStr.c_str(), dashedStr.size()) == 0) {
        // natoms is not known, so the loop proceeds till the bottom dashed line
        // is encountered
        while (true) {
          getline(inStream, buffer);
          // Condition for encountering dashed line
          if (strncmp(buffer.c_str(), dashedStr.c_str(), dashedStr.size()) ==
              0) {
            if (coordSet == 0) {
              mol.setCoordinate3d(mol.atomPositions3d(), coordSet++);
              positions.reserve(natoms);
            } else {
              mol.setCoordinate3d(positions, coordSet++);
              positions.clear();
            }
            break;
          }
          // Parsing the coordinates
          stringSplit = split(buffer, ' ');
          Vector3 tmpAtom(lexicalCast<double>(stringSplit.at(0)),
                          lexicalCast<double>(stringSplit.at(1)),
                          lexicalCast<double>(stringSplit.at(2)));
          if (coordSet == 0) {
            AtomTypeMap::const_iterator it;
            atomTypes.insert(
              std::make_pair(std::to_string(natoms), customElementCounter++));
            it = atomTypes.find(std::to_string(natoms));
            // if (customElementCounter > CustomElementMax) {
            //   appendError("Custom element type limit exceeded.");
            //   return false;
            // }
            Atom newAtom = mol.addAtom(it->second);
            newAtom.setPosition3d(tmpAtom);
            natoms++;
          } else {
            positions.push_back(tmpAtom);
          }
        }
      }
    }
  }

  // Set the custom element map if needed:
  if (!atomTypes.empty()) {
    Molecule::CustomElementMap elementMap;
    for (AtomTypeMap::const_iterator it = atomTypes.begin(),
                                     itEnd = atomTypes.end();
         it != itEnd; ++it) {
      elementMap.insert(std::make_pair(it->second, "Atom " + it->first));
    }
    mol.setCustomElementMap(elementMap);
  }

  return true;
}

bool OutcarFormat::write(std::ostream& outStream, const Core::Molecule& mol)
{
  return false;
}

std::vector<std::string> OutcarFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("OUTCAR");
  return ext;
}

std::vector<std::string> OutcarFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("N/A");
  return mime;
}

} // end Io namespace
} // end Avogadro namespace
