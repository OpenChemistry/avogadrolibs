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
#include <iostream>
#include <sstream>
#include <string>

using json = nlohmann::json;

using std::endl;
using std::getline;
using std::string;

namespace Avogadro::Io {

using Core::Array;
using Core::Atom;
using Core::Elements;
using Core::lexicalCast;
using Core::split;
using Core::trimmed;

#ifndef _WIN32
using std::isalpha;
#endif

std::optional<double> findEnergy(const std::string& buffer)
{
  // Check for energy in the comment line
  // orca uses  E -680.044112849966 (with spaces)
  // xtb uses energy: -680.044112849966
  // Open Babel uses Energy: -680.044112849966
  std::size_t energyStart = buffer.find("energy:");
  std::size_t offset = 7;
  if (energyStart == std::string::npos) {
    energyStart = buffer.find("Energy:");
  }
  if (energyStart == std::string::npos) {
    energyStart = buffer.find(" E ");
    offset = 3;
  }

  if (energyStart != std::string::npos) {
    // pick the next token
    std::string energy = buffer.substr(energyStart + offset);
    return lexicalCast<double>(energy);
  }
  return std::nullopt;
}

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
  if (!inStream.good()) {
    appendError("Error reading first line.");
    return false;
  }
  getline(inStream, buffer); // comment or name or energy
  if (!buffer.empty())
    mol.setData("name", trimmed(buffer));

  std::vector<double> energies;
  if (auto energy = findEnergy(buffer)) {
    mol.setData("totalEnergy", *energy);
    energies.push_back(*energy);
  }

  // check for Lattice= in an extended XYZ from ASE and company
  // e.g. Lattice="H11 H21 H31 H12 H22 H32 H13 H23 H33"
  // https://atomsk.univ-lille.fr/doc/en/format_xyz.html
  // https://gitlab.com/ase/ase/-/merge_requests/62
  std::size_t start = buffer.find("Lattice=");
  if (start != std::string::npos) {
    // step through bit by bit until we hit the next quote character
    start = start + 8;
    // skip over the first quote
    if (buffer[start] == '\"') {
      start++;
    }
    std::size_t end = buffer.find('\"', start);
    std::string lattice = buffer.substr(start, (end - start));

    std::vector<string> tokens(split(lattice, ' '));

    // check for size
    std::cout << "Lattice size: " << tokens.size() << std::endl;

    if (tokens.size() >= 9) {
      if (auto tmp = lexicalCast<double>(tokens.begin(), tokens.begin() + 9)) {
        Vector3 v1(tmp->at(0), tmp->at(1), tmp->at(2));
        Vector3 v2(tmp->at(3), tmp->at(4), tmp->at(5));
        Vector3 v3(tmp->at(6), tmp->at(7), tmp->at(8));

        auto* cell = new Core::UnitCell(v1, v2, v3);
        std::cout << " Lattice: " << cell->aVector() << " " << cell->bVector()
                  << " " << cell->cVector() << std::endl;
        if (!cell->isRegular()) {
          appendError("Lattice vectors are not linear independent");
          delete cell;
        } else {
          mol.setUnitCell(cell);
        }
      } else {
        appendError("Lattice vectors are malformed");
      }
    }
  }
  // check to see if there's an extended XYZ Properties= line
  // e.g. Properties=species:S:1:pos:R:3
  // https://gitlab.com/ase/ase/-/merge_requests/62
  start = buffer.find("Properties=");
  unsigned int chargeColumn = 0;
  unsigned int forceColumn = 0;
  std::vector<double> charges;
  if (start != std::string::npos) {
    start = start + 11; // skip over "Properties="
    unsigned int stop = buffer.find(' ', start);
    unsigned int length = stop - start;
    // we want to track columns after the position
    // (esp. charge, spin, force, velocity, etc.)
    std::string properties = buffer.substr(start, length);
    std::vector<string> tokens(split(properties, ':'));
    unsigned int column = 0;
    for (size_t i = 0; i < tokens.size(); i += 3) {
      // we can safely assume species and pos are present
      if (tokens[i] == "charge") {
        chargeColumn = column;
      } else if (tokens[i] == "force" || tokens[i] == "forces") {
        forceColumn = column;
      } // TODO other properties (velocity, spin, selection, etc.)

      // increment column based on the count of the property
      if (i + 2 < tokens.size()) {
        if (auto c = lexicalCast<unsigned int>(tokens[i + 2])) {
          column += *c;
        } else {
          appendError("Error reading property column: " + tokens[i + 2]);
        }
      }
    }
  }

  if (!inStream.good()) {
    appendError("Error reading comment line.");
    return false;
  }

  // Parse atoms
  for (size_t i = 0; i < numAtoms; ++i) {
    getline(inStream, buffer);
    if (!inStream.good()) {
      appendError("Error reading atom at index " + std::to_string(i) + ".");
      return false;
    }

    std::vector<string> tokens;
    // check for tabs PR#1512
    if (buffer.find('\t') != std::string::npos)
      tokens = split(buffer, '\t');
    else
      tokens = split(buffer, ' ');

    if (tokens.size() < 4) {
      appendError("Not enough tokens in this line: " + buffer);
      return false;
    }

    unsigned char atomicNum(0);
    if (isalpha(tokens[0][0]))
      atomicNum = Elements::atomicNumberFromSymbol(tokens[0]);
    else
      atomicNum = static_cast<unsigned char>(
        lexicalCast<short int>(tokens[0]).value_or(0));

    Vector3 pos;
    if (auto tmp =
          lexicalCast<double>(tokens.begin() + 1, tokens.begin() + 4)) {
      pos << tmp->at(0), tmp->at(1), tmp->at(2);
    } else {
      appendError("Error reading atom position");
      return false;
    }

    Atom newAtom = mol.addAtom(atomicNum);
    newAtom.setPosition3d(pos);

    // check for charge and force columns
    if (chargeColumn > 0 && chargeColumn < tokens.size()) {
      if (auto c = lexicalCast<double>(tokens[chargeColumn])) {
        charges.push_back(*c);
      } else {
        appendError("Error reading charge");
      }
      // we set the charges after all atoms are added
    }
    if (forceColumn > 0 && forceColumn < tokens.size()) {
      if (auto tmp = lexicalCast<double>(tokens.begin() + forceColumn,
                                         tokens.begin() + forceColumn + 3)) {
        Vector3 force(tmp->at(0), tmp->at(1), tmp->at(2));
        newAtom.setForceVector(force);
      } else {
        appendError("Error reading force");
      }
    }
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
  // check if the next frame has the same number of atoms
  getline(inStream, buffer); // should be the number of atoms
  if (buffer.size() == 0 || buffer[0] == '>') {
    getline(inStream, buffer); // Orca 6 prints ">" separators
  }

  auto numAtoms2 = lexicalCast<int>(buffer);
  if (numAtoms2 && numAtoms == *numAtoms2) {
    getline(inStream, buffer); // comment line
    // check for properties in the comment line
    if (auto energy = findEnergy(buffer)) {
      energies.push_back(*energy);
    }

    mol.setCoordinate3d(mol.atomPositions3d(), 0);
    int coordSet = 1;
    bool done = false;
    while (numAtoms == numAtoms2) {
      Array<Vector3> positions;
      positions.reserve(numAtoms);

      for (size_t i = 0; i < numAtoms; ++i) {
        getline(inStream, buffer);
        if (inStream.eof()) {
          numAtoms2 = 0;
          done = true;
          break; // break this inner loop
        }

        std::vector<string> tokens(split(buffer, ' '));
        if (tokens.size() < 4) {
          appendError("Not enough tokens in this line: " + buffer);
          return false;
        }
        if (auto tmp =
              lexicalCast<double>(tokens.begin() + 1, tokens.begin() + 4)) {
          Vector3 pos(tmp->at(0), tmp->at(1), tmp->at(2));
          positions.push_back(pos);
        } else {
          appendError("Error reading position");
          return false;
        }
      }

      if (!done)
        mol.setCoordinate3d(positions, coordSet++);

      if (getline(inStream, buffer)) {
        if (inStream.eof()) {
          numAtoms2 = 0;
          break; // break this inner loop
        }

        if (buffer.size() == 0 || buffer[0] == '>')
          getline(inStream, buffer); // Orca 6 prints ">" separators
        if (inStream.eof()) {
          numAtoms2 = 0;
          break; // break this inner loop
        }

        numAtoms2 = lexicalCast<int>(buffer);
        if (numAtoms != numAtoms2)
          break;
      }

      std::getline(inStream, buffer); // Skip the blank
      // check for energies
      if (auto energy = findEnergy(buffer)) {
        energies.push_back(*energy);
      }
      positions.clear();
    }
  }

  // This format has no connectivity information, so perceive basics at least.
  if (opts.value("perceiveBonds", true)) {
    mol.perceiveBondsSimple();
    mol.perceiveBondOrders();
  }

  // have to set the charges after creating bonds
  // (since modifying bonds invalidates the partial charges)
  if (!charges.empty()) {
    MatrixX chargesMatrix = MatrixX::Zero(mol.atomCount(), 1);
    for (size_t i = 0; i < charges.size(); ++i) {
      chargesMatrix(i, 0) = charges[i];
    }
    mol.setPartialCharges("From File", chargesMatrix);
  }

  if (energies.size() > 1)
    mol.setData("energies", energies);

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
              << Elements::symbol(atom.atomicNumber()) << " " << std::setw(15)
              << std::right << std::fixed << std::setprecision(10)
              << atom.position3d().x() << " " << std::setw(15) << std::right
              << std::fixed << std::setprecision(10) << atom.position3d().y()
              << " " << std::setw(15) << std::right << std::fixed
              << std::setprecision(10) << atom.position3d().z() << "\n";
  }

  return true;
}

std::vector<std::string> XyzFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.emplace_back("xyz");
  ext.emplace_back("exyz");
  ext.emplace_back("extxyz");
  ext.emplace_back("allxyz");
  return ext;
}

std::vector<std::string> XyzFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.emplace_back("chemical/x-xyz");
  return mime;
}

} // namespace Avogadro::Io
