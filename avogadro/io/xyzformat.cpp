/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "xyzformat.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <nlohmann/json.hpp>

#include <iomanip>
#include <istream>
#include <ostream>
#include <sstream>
#include <string>

using json = nlohmann::json;

using std::endl;
using std::getline;
using std::string;
using std::string;
using std::vector;

namespace Avogadro {
namespace Io {

using Core::Array;
using Core::Atom;
using Core::Elements;
using Core::Molecule;
using Core::lexicalCast;
using Core::split;
using Core::trimmed;

#ifndef _WIN32
using std::isalpha;
#endif

XyzFormat::XyzFormat() {}

XyzFormat::~XyzFormat() {}

bool XyzFormat::read(std::istream& inStream, Core::Molecule& mol)
{
  json opts;
  if (!options().empty())
    opts = json::parse(options(), nullptr, false);
  else
    opts = json::object();

  size_t numAtoms = 0;
  if (!(inStream >> numAtoms)) {
    appendError("Error parsing number of atoms.");
    return false;
  }

  string buffer;
  getline(inStream, buffer); // Finish the first line
  getline(inStream, buffer);
  if (!buffer.empty())
    mol.setData("name", trimmed(buffer));

  // check for Lattice= in an extended XYZ from ASE and company
  // e.g. Lattice="H11 H21 H31 H12 H22 H32 H13 H23 H33"
  // https://atomsk.univ-lille.fr/doc/en/format_xyz.html
  // https://gitlab.com/ase/ase/-/merge_requests/62
  std::size_t start = buffer.find("Lattice=\"");
  if (start != std::string::npos) {
    // step through bit by bit until we hit the next quote character
    start = start + 9;
    std::size_t end = buffer.find('\"', start);
    std::string lattice = buffer.substr(start, (end - start));

    vector<string> tokens(split(lattice, ' '));
    if (tokens.size() == 9) {
      Vector3 v1(lexicalCast<double>(tokens[0]), lexicalCast<double>(tokens[1]),
                 lexicalCast<double>(tokens[2]));
      Vector3 v2(lexicalCast<double>(tokens[3]), lexicalCast<double>(tokens[4]),
                 lexicalCast<double>(tokens[5]));
      Vector3 v3(lexicalCast<double>(tokens[6]), lexicalCast<double>(tokens[7]),
                 lexicalCast<double>(tokens[8]));

      Core::UnitCell* cell = new Core::UnitCell(v1, v2, v3);
      mol.setUnitCell(cell);
    }
  }

  // Parse atoms
  for (size_t i = 0; i < numAtoms; ++i) {
    getline(inStream, buffer);
    vector<string> tokens(split(buffer, ' '));

    if (tokens.size() < 4) {
      appendError("Not enough tokens in this line: " + buffer);
      return false;
    }

    unsigned char atomicNum(0);
    if (isalpha(tokens[0][0]))
      atomicNum = Elements::atomicNumberFromSymbol(tokens[0]);
    else
      atomicNum = static_cast<unsigned char>(lexicalCast<short int>(tokens[0]));

    Vector3 pos(lexicalCast<double>(tokens[1]), lexicalCast<double>(tokens[2]),
                lexicalCast<double>(tokens[3]));

    Atom newAtom = mol.addAtom(atomicNum);
    newAtom.setPosition3d(pos);
  }

  // Check that all atoms were handled.
  if (mol.atomCount() != numAtoms) {
    std::ostringstream errorStream;
    errorStream << "Error parsing atom at index " << mol.atomCount()
                << " (line " << 3 + mol.atomCount() << ").\n"
                << buffer;
    appendError(errorStream.str());
    return false;
  }

  // Do we have an animation?
  size_t numAtoms2;
  if (getline(inStream, buffer) && (numAtoms2 = lexicalCast<int>(buffer)) &&
      numAtoms == numAtoms2) {
    getline(inStream, buffer); // Skip the blank
    mol.setCoordinate3d(mol.atomPositions3d(), 0);
    int coordSet = 1;
    while (numAtoms == numAtoms2) {
      Array<Vector3> positions;
      positions.reserve(numAtoms);

      for (size_t i = 0; i < numAtoms; ++i) {
        getline(inStream, buffer);
        vector<string> tokens(split(buffer, ' '));
        if (tokens.size() < 4) {
          appendError("Not enough tokens in this line: " + buffer);
          return false;
        }
        Vector3 pos(lexicalCast<double>(tokens[1]),
                    lexicalCast<double>(tokens[2]),
                    lexicalCast<double>(tokens[3]));
        positions.push_back(pos);
      }

      mol.setCoordinate3d(positions, coordSet++);

      if (!getline(inStream, buffer)) {
        numAtoms2 = lexicalCast<int>(buffer);
        if (numAtoms == numAtoms2)
          break;
      }

      std::getline(inStream, buffer); // Skip the blank
      positions.clear();
    }
  }

  // This format has no connectivity information, so perceive basics at least.
  if (opts.value("perceiveBonds", true))
    mol.perceiveBondsSimple();

  return true;
}

bool XyzFormat::write(std::ostream& outStream, const Core::Molecule& mol)
{
  size_t numAtoms = mol.atomCount();

  outStream << numAtoms << std::endl;

  if (mol.unitCell()) {
    // default to including Lattice for extended XYZ if present
    // https://atomsk.univ-lille.fr/doc/en/format_xyz.html
    // https://gitlab.com/ase/ase/-/merge_requests/62
    outStream << "Lattice=\"";
    outStream << mol.unitCell()->aVector().x() << ' ';
    outStream << mol.unitCell()->aVector().y() << ' ';
    outStream << mol.unitCell()->aVector().z() << ' ';

    outStream << mol.unitCell()->bVector().x() << ' ';
    outStream << mol.unitCell()->bVector().y() << ' ';
    outStream << mol.unitCell()->bVector().z() << ' ';

    outStream << mol.unitCell()->cVector().x() << ' ';
    outStream << mol.unitCell()->cVector().y() << ' ';
    outStream << mol.unitCell()->cVector().z();

    outStream << "\" Properties=species:S:1:pos:R:3" << endl;
  } else {
    if (mol.data("name").toString().length())
      outStream << mol.data("name").toString() << endl;
    else
      outStream << "XYZ file generated by Avogadro.\n";
  }

  for (size_t i = 0; i < numAtoms; ++i) {
    Atom atom = mol.atom(i);
    if (!atom.isValid()) {
      appendError("Internal error: Atom invalid.");
      return false;
    }

    outStream << std::setw(3) << std::left
              << Elements::symbol(atom.atomicNumber()) << " " << std::setw(10)
              << std::right << std::fixed << std::setprecision(5)
              << atom.position3d().x() << " " << std::setw(10) << std::right
              << std::fixed << std::setprecision(5) << atom.position3d().y()
              << " " << std::setw(10) << std::right << std::fixed
              << std::setprecision(5) << atom.position3d().z() << "\n";
  }

  return true;
}

std::vector<std::string> XyzFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("xyz");
  ext.push_back("extxyz");
  return ext;
}

std::vector<std::string> XyzFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("chemical/x-xyz");
  return mime;
}

} // namespace Io
} // namespace Avogadro
