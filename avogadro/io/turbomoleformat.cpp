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
#include <sstream>
#include <string>

using json = nlohmann::json;

using std::endl;
using std::getline;
using std::string;
using std::vector;

namespace Avogadro::Io {

using Core::Array;
using Core::Atom;
using Core::Elements;
using Core::lexicalCast;
using Core::Molecule;
using Core::split;
using Core::trimmed;

#ifndef _WIN32
using std::isalpha;
#endif

TurbomoleFormat::TurbomoleFormat() {}

TurbomoleFormat::~TurbomoleFormat() {}

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
  // defaults if periodicity is not 3
  Vector3 v1(100.0, 0.0, 0.0);
  Vector3 v2(0.0, 100.0, 0.0);
  Vector3 v3(0.0, 0.0, 100.0);

  // we loop through each line until we hit $end or EOF
  string buffer;
  getline(inStream, buffer);
  while (inStream.good() && !buffer.empty()) {
    if (buffer.find("$end") != std::string::npos)
      break;
    else if (buffer.find("$coord") != std::string::npos) {
      // check if there's a conversion to be done
      Real coordConversion = BOHR_TO_ANGSTROM; // default is Bohr
      if (buffer.find("ang") != std::string::npos)
        coordConversion = 1.0; // leave as Angstrom
      else if (buffer.find("frac") != std::string::npos) {
        fractionalCoords = true;
        coordConversion = 1.0; // we may not know the lattice constants yet
      }

      getline(inStream, buffer);
      while (buffer.find("$") == std::string::npos) {
        // parse atoms until we see another '$' section
        // e.g. 0.0000      0.000000     -0.73578      o
        vector<string> tokens(split(buffer, ' '));

        if (tokens.size() < 4) {
          appendError("Not enough tokens in this line: " + buffer);
          return false;
        }

        unsigned char atomicNum(0);
        if (isalpha(tokens[3][0])) {
          tokens[3][0] = toupper(tokens[3][0]);
          atomicNum = Elements::atomicNumberFromSymbol(tokens[3]);
        } else
          atomicNum =
            static_cast<unsigned char>(lexicalCast<short int>(tokens[3]));

        Vector3 pos(lexicalCast<double>(tokens[0]),
                    lexicalCast<double>(tokens[1]),
                    lexicalCast<double>(tokens[2]));

        Atom newAtom = mol.addAtom(atomicNum);
        newAtom.setPosition3d(pos * coordConversion);

        // next line
        getline(inStream, buffer);
        continue;
      }
    } else if (buffer.find("$cell") != std::string::npos) {
      hasCell = true;
      Real cellConversion = BOHR_TO_ANGSTROM;
      if (buffer.find("ang") != std::string::npos)
        cellConversion = 1.0; // leave as Angstrom

      getline(inStream, buffer);
      vector<string> tokens(split(buffer, ' '));
      if (tokens.size() < 6) {
        appendError("Not enough tokens in this line: " + buffer);
        return false;
      }
      a = lexicalCast<double>(tokens[0]) * cellConversion;
      b = lexicalCast<double>(tokens[1]) * cellConversion;
      c = lexicalCast<double>(tokens[2]) * cellConversion;
      alpha = lexicalCast<double>(tokens[3]) * DEG_TO_RAD;
      beta = lexicalCast<double>(tokens[4]) * DEG_TO_RAD;
      gamma = lexicalCast<double>(tokens[5]) * DEG_TO_RAD;

    } else if (buffer.find("$lattice") != std::string::npos) {
      hasLattice = true;
      Real latticeConversion = BOHR_TO_ANGSTROM; // default
      if (buffer.find("ang") != std::string::npos)
        latticeConversion = 1.0; // leave as Angstrom

      for (int line = 0; line < 3; ++line) {
        getline(inStream, buffer);
        vector<string> tokens(split(buffer, ' '));
        if (tokens.size() < 3)
          break;

        if (line == 0) {
          v1.x() = lexicalCast<double>(tokens[0]) * latticeConversion;
          v1.y() = lexicalCast<double>(tokens[1]) * latticeConversion;
          v1.z() = lexicalCast<double>(tokens[2]) * latticeConversion;
        } else if (line == 1) {
          v2.x() = lexicalCast<double>(tokens[0]) * latticeConversion;
          v2.y() = lexicalCast<double>(tokens[1]) * latticeConversion;
          v2.z() = lexicalCast<double>(tokens[2]) * latticeConversion;
        } else if (line == 2) {
          v3.x() = lexicalCast<double>(tokens[0]) * latticeConversion;
          v3.y() = lexicalCast<double>(tokens[1]) * latticeConversion;
          v3.z() = lexicalCast<double>(tokens[2]) * latticeConversion;
        }
      }
    }

    getline(inStream, buffer);
  } // done reading the file

  if (hasLattice) {
    auto* cell = new Core::UnitCell(v1, v2, v3);
    mol.setUnitCell(cell);
  } else if (hasCell) {
    auto* cell = new Core::UnitCell(a, b, c, alpha, beta, gamma);
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
  if (opts.value("perceiveBonds", true))
    mol.perceiveBondsSimple();

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
              << std::setw(5)
              << std::right << symbol << "\n";
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
  return ext;
}

std::vector<std::string> TurbomoleFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.emplace_back("chemical/x-turbomole");
  return mime;
}

} // namespace Avogadro::Io
