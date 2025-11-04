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
#include <optional>
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
  Real a = 100.0, b = 100.0, c = 100.0;
  Real alpha = 90.0 * DEG_TO_RAD, beta = 90.0 * DEG_TO_RAD,
       gamma = 90.0 * DEG_TO_RAD;
  // defaults if periodicity is not 3
  Vector3 v1(100.0, 0.0, 0.0);
  Vector3 v2(0.0, 100.0, 0.0);
  Vector3 v3(0.0, 0.0, 100.0);
  std::optional<unsigned> periodic_parsed, periodic_guessed;

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

    if (tokens[0] == "$periodic") {
      if (tokens.size() != 2u) {
        appendError("Not enough or extra tokens in this line: " + buffer);
        return false;
      }

      if (auto tmp = lexicalCast<int>(tokens[1])) {
        if (*tmp < 0 || *tmp > 3) {
          appendError("Invalid dimensionality: " + buffer);
          return false;
        }
        periodic_parsed = static_cast<unsigned>(*tmp);
      } else {
        appendError("Failed to parse: " + buffer);
        return false;
      }
      getline(inStream, buffer);
      continue;
    }

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
      if (hasLattice) {
        appendError("Both of $cell and $lattice are specified");
        return false;
      }
      hasCell = true;
      Real cellConversion = BOHR_TO_ANGSTROM;
      if (std::find(tokens.begin(), tokens.end(), "angs") != tokens.end())
        cellConversion = 1.0; // leave as Angstrom

      getline(inStream, buffer);
      tokens = split(rstrip(buffer, '#'), ' ');
      const auto tokens_converted =
        lexicalCast<double>(tokens.begin(), tokens.end());
      if (!tokens_converted) {
        appendError("Failed to parse: " + buffer);
        return false;
      }

      const auto ntokens = tokens_converted->size();

      auto set_cell_vars = [&](unsigned periodic) {
        if (periodic == 1) {
          a = tokens_converted->at(0) * cellConversion;
        } else if (periodic == 2) {
          a = tokens_converted->at(0) * cellConversion;
          b = tokens_converted->at(1) * cellConversion;
          gamma = tokens_converted->at(2) * DEG_TO_RAD;
        } else {
          a = tokens_converted->at(0) * cellConversion;
          b = tokens_converted->at(1) * cellConversion;
          c = tokens_converted->at(2) * cellConversion;
          alpha = tokens_converted->at(3) * DEG_TO_RAD;
          beta = tokens_converted->at(4) * DEG_TO_RAD;
          gamma = tokens_converted->at(5) * DEG_TO_RAD;
        }
      };

      if (periodic_parsed) {
        // $periodic appeared
        if ((*periodic_parsed == 1 && ntokens == 1) ||
            (*periodic_parsed == 2 && ntokens == 3) ||
            (*periodic_parsed == 3 && ntokens == 6)) {
          set_cell_vars(*periodic_parsed);
        } else if (*periodic_parsed == 0) {
          hasCell = false;
          std::cerr << "Ignore $cell since '$periodic 0' (non periodic) "
                       "is specified\n";
        } else {
          appendError("Not enough or extra tokens in this line: " + buffer);
          return false;
        }
      } else {
        // $periodic does not appear yet, so guess it from the number of the
        // elements
        if (ntokens == 1) {
          periodic_guessed = 1;
        } else if (ntokens == 3) {
          periodic_guessed = 2;
        } else if (ntokens == 6) {
          periodic_guessed = 3;
        } else {
          appendError("Cannot determine dimensionality from $cell: " + buffer);
          return false;
        }
        set_cell_vars(*periodic_guessed);
      }

    } else if (tokens[0] == "$lattice") {
      if (hasCell) {
        appendError("Both of $cell and $lattice are specified");
        return false;
      }
      hasLattice = true;
      Real latticeConversion = BOHR_TO_ANGSTROM; // default
      if (std::find(tokens.begin(), tokens.end(), "angs") != tokens.end())
        latticeConversion = 1.0; // leave as Angstrom

      if (periodic_parsed) {
        // $periodic appeared
        if (*periodic_parsed == 0) {
          hasLattice = false;
          std::cerr << "Ignore $lattice since '$periodic 0' (non periodic) "
                       "is specified\n";
        }

        for (unsigned line = 0; line < *periodic_parsed; ++line) {
          getline(inStream, buffer);
          tokens = split(rstrip(buffer, '#'), ' ');
          const auto tmp = lexicalCast<double>(tokens.begin(), tokens.end());
          if (!tmp) {
            appendError("Failed to parse this line following $lattice: " +
                        buffer);
            return false;
          }
          if (tmp->size() != *periodic_parsed) {
            appendError(
              "Not enough or extra tokens in this line following $lattice: " +
              buffer);
            return false;
          }

          if (line == 0) {
            v1.x() = tmp->at(0) * latticeConversion;
            v1.y() =
              *periodic_parsed == 1 ? 0.0 : tmp->at(1) * latticeConversion;
            v1.z() =
              *periodic_parsed < 3 ? 0.0 : tmp->at(2) * latticeConversion;
          } else if (line == 1) {
            v2.x() = tmp->at(0) * latticeConversion;
            v2.y() = tmp->at(1) * latticeConversion;
            v2.z() =
              *periodic_parsed < 3 ? 0.0 : tmp->at(2) * latticeConversion;
          } else if (line == 2) {
            v3.x() = tmp->at(0) * latticeConversion;
            v3.y() = tmp->at(1) * latticeConversion;
            v3.z() = tmp->at(2) * latticeConversion;
          }
        }
      } else {
        // $periodic does not appear yet, so guess dimensionality from line(s)
        // following $lattice
        for (unsigned line = 0; line < 3; ++line) {
          getline(inStream, buffer);
          tokens = split(rstrip(buffer, '#'), ' ');
          const auto tmp = lexicalCast<double>(tokens.begin(), tokens.end());
          if (!tmp) {
            appendError("Failed to parse: " + buffer);
            return false;
          }

          const auto n = tmp->size();
          if (line == 0) {
            if (n == 0u || n > 3u) {
              appendError("Could not determine dimensionality from lines "
                          "following $lattice:\n" +
                          buffer);
              return false;
            }
            periodic_guessed = n;
          } else if (*periodic_guessed != n) {
            appendError("The previous and current lines respectively have " +
                        std::to_string(*periodic_guessed) + " and " +
                        std::to_string(n) + " element(s)\n" + buffer);
            return false;
          }

          if (line == 0) {
            v1.x() = tmp->at(0) * latticeConversion;
            if (n < 2)
              break;
            v1.y() = tmp->at(1) * latticeConversion;
            v1.z() = n != 3 ? 0.0 : tmp->at(2) * latticeConversion;
          } else if (line == 1) {
            v2.x() = tmp->at(0) * latticeConversion;
            v2.y() = tmp->at(1) * latticeConversion;
            if (n < 3)
              break;
            v2.z() = tmp->at(2) * latticeConversion;
          } else if (line == 2) {
            v3.x() = tmp->at(0) * latticeConversion;
            v3.y() = tmp->at(1) * latticeConversion;
            v3.z() = tmp->at(2) * latticeConversion;
          }
        }
      }

    } else if (tokens[0][0] != '#') {
      std::cerr << "Ignore unknown token: " << buffer << '\n';
    }

    getline(inStream, buffer);
  } // done reading the file

  if (periodic_parsed && *periodic_parsed > 0 && (!hasLattice && !hasCell)) {
    appendError("$periodic specifies " + std::to_string(*periodic_parsed) +
                " but neither $cell nor $lattice appears");
    return false;
  }

  if (periodic_parsed && periodic_guessed &&
      *periodic_parsed != *periodic_guessed) {
    appendError("Dimensionality guessed from $lattice/$cell is " +
                std::to_string(*periodic_guessed) +
                " but $periodic specifies " + std::to_string(*periodic_parsed));
    return false;
  }

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
