/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "pdbformat.h"

#include "avogadro/core/avogadrocore.h"
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/secondarystructure.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <cctype>
#include <iostream>
#include <istream>
#include <string>

using Avogadro::Core::Array;
using Avogadro::Core::Atom;
using Avogadro::Core::Elements;
using Avogadro::Core::lexicalCast;
using Avogadro::Core::Residue;
using Avogadro::Core::SecondaryStructureAssigner;
using Avogadro::Core::startsWith;
using Avogadro::Core::trimmed;

using std::getline;
using std::istringstream;
using std::string;

namespace Avogadro::Io {

bool PdbFormat::read(std::istream& in, Core::Molecule& mol)
{
  string buffer;
  std::vector<int> terList;
  Residue* r = nullptr;
  size_t currentResidueId = 0;
  bool ok(false);
  int coordSet = 0;
  Array<Vector3> positions;
  Array<size_t> rawToAtomId;
  Array<size_t> altAtomIds;
  Array<int> altAtomCoordSets;
  Array<char> altAtomLocs;
  std::set<char> altLocs;
  Array<Vector3> altAtomPositions;

  while (getline(in, buffer)) { // Read Each line one by one
    if (!in.good())
      break;

    if (startsWith(buffer, "ENDMDL")) {
      if (coordSet == 0) {
        mol.setCoordinate3d(mol.atomPositions3d(), coordSet++);
        positions.reserve(mol.atomCount());
      } else {
        mol.setCoordinate3d(positions, coordSet++);
        positions.clear();
      }
    }

    // e.g.   CRYST1    4.912    4.912    6.696  90.00  90.00 120.00 P1 1
    // https://www.wwpdb.org/documentation/file-format-content/format33/sect8.html
    else if (startsWith(buffer, "CRYST1") && buffer.length() >= 55) {
      // PDB reports in degrees and Angstroms
      //   Avogadro uses radians internally
      auto a = lexicalCast<Real>(buffer.substr(6, 9));
      auto b = lexicalCast<Real>(buffer.substr(15, 9));
      auto c = lexicalCast<Real>(buffer.substr(24, 9));
      auto alpha = lexicalCast<Real>(buffer.substr(33, 7));
      auto beta = lexicalCast<Real>(buffer.substr(40, 7));
      auto gamma = lexicalCast<Real>(buffer.substr(47, 8));

      if (!a || !b || !c || !alpha || !beta || !gamma) {
        appendError("Failed to parse CRYST1 :" + buffer);
        return false;
      }

      auto* cell = new Core::UnitCell(*a, *b, *c, *alpha * DEG_TO_RAD,
                                      *beta * DEG_TO_RAD, *gamma * DEG_TO_RAD);
      if (!cell->isRegular()) {
        appendError("CRYST1 does not give linear independent lattice vectors");
        delete cell;
        return false;
      }
      mol.setUnitCell(cell);
    }

    else if (startsWith(buffer, "ATOM") || startsWith(buffer, "HETATM")) {
      if (buffer.length() < 54) {
        appendError("Error reading line.");
        return false;
      }

      // First we initialize the residue instance
      auto residueId = lexicalCast<size_t>(buffer.substr(22, 4), ok);
      if (!ok) {
        appendError("Failed to parse residue sequence number: " +
                    buffer.substr(22, 4));
        return false;
      }

      if (residueId != currentResidueId) {
        currentResidueId = residueId;

        auto residueName = lexicalCast<string>(buffer.substr(17, 3), ok);
        if (!ok) {
          appendError("Failed to parse residue name: " + buffer.substr(17, 3));
          return false;
        }

        char chainId = lexicalCast<char>(buffer.substr(21, 1), ok);
        if (!ok) {
          chainId = 'A'; // it's a non-standard "PDB"-like file
        }

        r = &mol.addResidue(residueName, currentResidueId, chainId);
        if (startsWith(buffer, "HETATM"))
          r->setHeterogen(true);
      }

      auto atomName = lexicalCast<string>(buffer.substr(12, 4), ok);
      if (!ok) {
        appendError("Failed to parse atom name: " + buffer.substr(12, 4));
        return false;
      }

      Vector3 pos; // Coordinates
      pos.x() = lexicalCast<Real>(buffer.substr(30, 8), ok);
      if (!ok) {
        appendError("Failed to parse x coordinate: " + buffer.substr(30, 8));
        return false;
      }

      pos.y() = lexicalCast<Real>(buffer.substr(38, 8), ok);
      if (!ok) {
        appendError("Failed to parse y coordinate: " + buffer.substr(38, 8));
        return false;
      }

      pos.z() = lexicalCast<Real>(buffer.substr(46, 8), ok);
      if (!ok) {
        appendError("Failed to parse z coordinate: " + buffer.substr(46, 8));
        return false;
      }

      auto altLoc = lexicalCast<string>(buffer.substr(16, 1), ok);

      string element; // Element symbol, right justified
      unsigned char atomicNum = 255;
      if (buffer.size() >= 78) {
        element = buffer.substr(76, 2);
        element = trimmed(element);
        if (element.length() == 2)
          element[1] = std::tolower(element[1]);

        atomicNum = Elements::atomicNumberFromSymbol(element);
        if (atomicNum == 255)
          appendError("Invalid element");
      }

      if (atomicNum == 255) {
        // non-standard or old-school PDB file - try to parse the atom name
        element = trimmed(atomName);
        // remove any trailing digits
        while (element.size() && std::isdigit(element.back()))
          element.pop_back();

        if (element == "SE") // For Sulphur
          element = 'S';

        atomicNum = Elements::atomicNumberFromSymbol(element);
        if (atomicNum == 255) {
          appendError("Invalid element");
          continue; // skip this invalid record
        }
      }

      if (altLoc.compare("") && altLoc.compare("A")) {
        if (coordSet == 0) {
          rawToAtomId.push_back(-1);
          altAtomIds.push_back(mol.atomCount() - 1);
        } else {
          altAtomIds.push_back(positions.size() - 1);
        }
        altAtomCoordSets.push_back(coordSet);
        altAtomLocs.push_back(altLoc[0]);
        altLocs.insert(altLoc[0]);
        altAtomPositions.push_back(pos);
      } else if (coordSet == 0) {
        Atom newAtom = mol.addAtom(atomicNum);
        newAtom.setPosition3d(pos);
        if (r != nullptr) {
          r->addResidueAtom(atomName, newAtom);
        }
        rawToAtomId.push_back(mol.atomCount() - 1);
      } else {
        positions.push_back(pos);
      }
    }

    else if (startsWith(buffer, "TER") &&
             buffer.length() >= 11) { //  This is very important, each TER
                                      //  record also counts in the serial.
      // Need to account for that when comparing with CONECT
      terList.push_back(lexicalCast<int>(buffer.substr(6, 5), ok));

      if (!ok) {
        appendError("Failed to parse TER serial");
        return false;
      }
    }

    else if (startsWith(buffer, "CONECT")) {
      if (buffer.length() < 16) {
        appendError("Error reading line.");
        return false;
      }

      int a = lexicalCast<int>(buffer.substr(6, 5), ok);
      if (!ok) {
        appendError("Failed to parse bond connection a " + buffer.substr(6, 5));
        return false;
      }
      --a;
      size_t terCount;
      for (terCount = 0; terCount < terList.size() && a > terList[terCount];
           ++terCount)
        ; // semicolon is intentional
      a = a - terCount;
      a = rawToAtomId[a];

      int bCoords[] = { 11, 16, 21, 26 };
      for (int i = 0; i < 4; i++) {
        if (trimmed(buffer.substr(bCoords[i], 5)) == "")
          break;

        else {
          int b = lexicalCast<int>(buffer.substr(bCoords[i], 5), ok) - 1;
          if (!ok) {
            appendError("Failed to parse bond connection b" +
                        std::to_string(i) + " " + buffer.substr(bCoords[i], 5));
            // return false;
            continue; // skip this invalid record
          }

          for (terCount = 0; terCount < terList.size() && b > terList[terCount];
               ++terCount)
            ; // semicolon is intentional
          b = b - terCount;
          b = rawToAtomId[b];

          if (a >= 0 && b >= 0) {
            auto aIndex = static_cast<Avogadro::Index>(a);
            auto bIndex = static_cast<Avogadro::Index>(b);
            if (aIndex < mol.atomCount() && bIndex < mol.atomCount()) {
              mol.Avogadro::Core::Molecule::addBond(aIndex, bIndex, 1);
            } else {
              appendError("Invalid bond connection: " + std::to_string(a) +
                          " - " + std::to_string(b));
            }
          }
        }
      }
    }
  } // End while loop

  if (mol.atomCount() == 0) {
    appendError("No atoms found in this file.");
    return false;
  }

  int count = mol.coordinate3dCount() ? mol.coordinate3dCount() : 1;
  for (int c = 0; c < count; ++c) {
    for (char l : altLocs) {
      Array<Vector3> coordinateSet =
        c == 0 ? mol.atomPositions3d() : mol.coordinate3d(c);
      bool found = false;
      for (size_t i = 0; i < altAtomCoordSets.size(); ++i) {
        if (altAtomCoordSets[i] == c && altAtomLocs[i] == l) {
          found = true;
          coordinateSet[altAtomIds[i]] = altAtomPositions[i];
        }
      }
      if (found)
        mol.setCoordinate3d(
          coordinateSet, mol.coordinate3dCount() ? mol.coordinate3dCount() : 1);
    }
  }

  mol.perceiveBondsSimple();
  mol.perceiveBondsFromResidueData();
  perceiveSubstitutedCations(mol);

  // if there are residue data, assign secondary structure
  if (mol.residueCount() != 0) {
    SecondaryStructureAssigner ssa;
    ssa.assign(&mol);
  }

  return true;
} // End read

std::vector<std::string> PdbFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.emplace_back("pdb");
  ext.emplace_back("ent");
  return ext;
}

std::vector<std::string> PdbFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.emplace_back("chemical/x-pdb");
  return mime;
}

void PdbFormat::perceiveSubstitutedCations(Core::Molecule& molecule)
{
  for (Index i = 0; i < molecule.atomCount(); i++) {
    unsigned char requiredBondCount(0);
    switch (molecule.atomicNumber(i)) {
      case 7:
      case 15:
      case 33:
      case 51:
        requiredBondCount = 4;
        break;
      case 8:
      case 16:
      case 34:
      case 52:
        requiredBondCount = 3;
    }
    if (!requiredBondCount)
      continue;

    unsigned char bondCount(0);
    Index j = 0;
    for (const auto& bond : molecule.bonds(i)) {
      unsigned char otherAtomicNumber(0);
      otherAtomicNumber = molecule.atomicNumber(bond.getOtherAtom(i).index());
      bondCount += bond.order();
      if (otherAtomicNumber && otherAtomicNumber != 6) {
        bondCount = 0;
        break;
      }
      j++;
    }

    if (bondCount == requiredBondCount) {
      molecule.setFormalCharge(i, 1);
    }
  }
}

} // namespace Avogadro::Io
