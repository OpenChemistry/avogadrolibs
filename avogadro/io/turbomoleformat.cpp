/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "turbomoleformat.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <nlohmann/json.hpp>

#include <iomanip>
#include <istream>
#include <ostream>
#include <string>

using json = nlohmann::json;

using std::getline;
using std::string;

namespace Avogadro::Io {

using Core::Atom;
using Core::Elements;
using Core::lexicalCast;
using Core::rstrip;
using Core::split;

#ifndef _WIN32
using std::isalpha;
#endif

bool TurbomoleFormat::read(std::istream& inStream, Core::Molecule& mol)
{
  json opts;
  if (!options().empty())
    opts = json::parse(options(), nullptr, false);
  else
    opts = json::object();

  bool hasCell = false;
  bool hasLattice = false;
  bool fractionalCoords = false;

  // possible lattice constants
  Real a, b, c, alpha, beta, gamma;
  a = b = c = 100.0;
  alpha = beta = gamma = 90.0;
  // defaults if periodicity is not 3
  Vector3 v1(100.0, 0.0, 0.0);
  Vector3 v2(0.0, 100.0, 0.0);
  Vector3 v3(0.0, 0.0, 100.0);

  // we loop through each line until we hit $end or EOF
  string buffer;
  getline(inStream, buffer);
  while (inStream.good() && !buffer.empty()) {
    std::vector<string> tokens = split(rstrip(buffer, '#'), ' ');
    if (tokens.empty()) { // "# comment line"
      getline(inStream, buffer);
      continue;
    }

    if (tokens[0] == "$end")
      break;

    if (tokens[0] == "$coord") {
      // check if there's a conversion to be done
      Real coordConversion = BOHR_TO_ANGSTROM; // default is Bohr
      if (std::find(tokens.begin(), tokens.end(), "ang") != tokens.end())
        coordConversion = 1.0; // leave as Angstrom
      else if (std::find(tokens.begin(), tokens.end(), "frac") !=
               tokens.end()) {
        fractionalCoords = true;
        coordConversion = 1.0; // we may not know the lattice constants yet
      } else if (tokens.size() > 1u && tokens[1][0] != '#') {
        std::cerr << "Ignore unknown trailing token and assume bohr: " << buffer
                  << '\n';
      }

      getline(inStream, buffer);
      tokens = split(rstrip(buffer, '#'), ' ');
      while (!tokens.empty() && tokens[0][0] != '$') {
        // parse atoms until we see another '$' section
        // e.g. 0.0000      0.000000     -0.73578      o

        if (tokens.size() < 4) {
          appendError("Not enough tokens in this line: " + buffer);
          return false;
        }

        unsigned char atomicNum(0);
        if (isalpha(tokens[3][0])) {
          tokens[3][0] = toupper(tokens[3][0]);
          atomicNum = Elements::atomicNumberFromSymbol(tokens[3]);
        } else
          atomicNum = static_cast<unsigned char>(
            lexicalCast<short int>(tokens[3]).value_or(0));

        Vector3 pos;
        if (auto tmp =
              lexicalCast<double>(tokens.begin(), tokens.begin() + 3)) {
          pos << tmp->at(0), tmp->at(1), tmp->at(2);
        } else {
          appendError("Failed to parse this line following $coord: " + buffer);
          return false;
        }

        Atom newAtom = mol.addAtom(atomicNum);
        newAtom.setPosition3d(pos * coordConversion);

        // next line
        getline(inStream, buffer);
        tokens = split(rstrip(buffer, '#'), ' ');
      }
    } else if (tokens[0] == "$cell") {
      hasCell = true;
      Real cellConversion = BOHR_TO_ANGSTROM;
      if (std::find(tokens.begin(), tokens.end(), "angs") != tokens.end())
        cellConversion = 1.0; // leave as Angstrom

      getline(inStream, buffer);
      tokens = split(rstrip(buffer, '#'), ' ');
      if (tokens.size() < 6) {
        appendError("Not enough tokens in this line: " + buffer);
        return false;
      }
      if (auto tmp = lexicalCast<double>(tokens.begin(), tokens.begin() + 6)) {
        a = tmp->at(0) * cellConversion;
        b = tmp->at(1) * cellConversion;
        c = tmp->at(2) * cellConversion;
        alpha = tmp->at(3) * DEG_TO_RAD;
        beta = tmp->at(4) * DEG_TO_RAD;
        gamma = tmp->at(5) * DEG_TO_RAD;
      } else {
        appendError("Failed to parse this line: " + buffer);
        return false;
      }

    } else if (tokens[0] == "$lattice") {
      hasLattice = true;
      Real latticeConversion = BOHR_TO_ANGSTROM; // default
      if (std::find(tokens.begin(), tokens.end(), "angs") != tokens.end())
        latticeConversion = 1.0; // leave as Angstrom

      for (int line = 0; line < 3; ++line) {
        getline(inStream, buffer);
        tokens = split(rstrip(buffer, '#'), ' ');
        if (tokens.size() < 3)
          break;

        if (auto tmp =
              lexicalCast<double>(tokens.begin(), tokens.begin() + 3)) {
          if (line == 0) {
            v1.x() = tmp->at(0) * latticeConversion;
            v1.y() = tmp->at(1) * latticeConversion;
            v1.z() = tmp->at(2) * latticeConversion;
          } else if (line == 1) {
            v2.x() = tmp->at(0) * latticeConversion;
            v2.y() = tmp->at(1) * latticeConversion;
            v2.z() = tmp->at(2) * latticeConversion;
          } else if (line == 2) {
            v3.x() = tmp->at(0) * latticeConversion;
            v3.y() = tmp->at(1) * latticeConversion;
            v3.z() = tmp->at(2) * latticeConversion;
          }
        } else {
          appendError("Failed to parse this line following $lattice: " +
                      buffer);
          return false;
        }
      }
    } else if (tokens[0][0] != '#') {
      std::cerr << "Ignore unknown token: " << buffer << '\n';
    }

    getline(inStream, buffer);
  } // done reading the file

  Core::UnitCell* cell = nullptr;
  std::string tmp;
  if (hasLattice) {
    cell = new Core::UnitCell(v1, v2, v3);
    tmp = "$lattice";
  } else if (hasCell) {
    cell = new Core::UnitCell(a, b, c, alpha, beta, gamma);
    tmp = "$cell";
  }
  if (cell) {
    if (!cell->isRegular()) {
      appendError(tmp + " does not give linear independent lattice vectors");
      delete cell;
      return false;
    }
    mol.setUnitCell(cell);
  }

  // if we have fractional coordinates, we need to convert them to cartesian
  if (fractionalCoords) {
    auto* cell = mol.unitCell();
    for (Index i = 0; i < mol.atomCount(); ++i) {
      mol.setAtomPosition3d(i, cell->toCartesian(mol.atomPosition3d(i)));
    }
  }

  // This format has no connectivity information, so perceive basics at least.
  if (opts.value("perceiveBonds", true)) {
    mol.perceiveBondsSimple();
    mol.perceiveBondOrders();
  }

  return true;
}

bool TurbomoleFormat::write(std::ostream& outStream, const Core::Molecule& mol)
{
  size_t numAtoms = mol.atomCount();

  outStream << "$coord angs\n";

  for (size_t i = 0; i < numAtoms; ++i) {
    Atom atom = mol.atom(i);
    if (!atom.isValid()) {
      appendError("Internal error: Atom invalid.");
      return false;
    }

    std::string symbol = Elements::symbol(atom.atomicNumber());
    symbol[0] = tolower(symbol[0]);

    outStream << " " << std::setw(18) << std::right << std::fixed
              << std::setprecision(10) << atom.position3d().x() << " "
              << std::setw(18) << std::right << std::fixed
              << std::setprecision(10) << atom.position3d().y() << " "
              << std::setw(18) << std::right << std::fixed
              << std::setprecision(10) << atom.position3d().z() << " "
              << std::setw(5) << std::right << symbol << "\n";
  }

  if (mol.unitCell()) {
    outStream << "$periodic 3\n";
    outStream << "$lattice angs\n";
    outStream << mol.unitCell()->aVector().x() << ' ';
    outStream << mol.unitCell()->aVector().y() << ' ';
    outStream << mol.unitCell()->aVector().z() << '\n';

    outStream << mol.unitCell()->bVector().x() << ' ';
    outStream << mol.unitCell()->bVector().y() << ' ';
    outStream << mol.unitCell()->bVector().z() << '\n';

    outStream << mol.unitCell()->cVector().x() << ' ';
    outStream << mol.unitCell()->cVector().y() << ' ';
    outStream << mol.unitCell()->cVector().z() << '\n';
  }

  outStream << "$end\n";

  return true;
}

std::vector<std::string> TurbomoleFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.emplace_back("coord");
  ext.emplace_back("tmol");
  return ext;
}

std::vector<std::string> TurbomoleFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.emplace_back("chemical/x-turbomole");
  return mime;
}

} // namespace Avogadro::Io
