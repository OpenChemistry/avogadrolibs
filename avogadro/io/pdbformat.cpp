/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "pdbformat.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <istream>
#include <string>

using Avogadro::Core::Array;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Elements;
using Avogadro::Core::lexicalCast;
using Avogadro::Core::Molecule;
using Avogadro::Core::Residue;
using Avogadro::Core::startsWith;
using Avogadro::Core::trimmed;

using std::getline;
using std::istringstream;
using std::string;
using std::vector;

namespace Avogadro {
namespace Io {

PdbFormat::PdbFormat() {}

PdbFormat::~PdbFormat() {}

bool PdbFormat::read(std::istream& in, Core::Molecule& mol)
{
  string buffer;
  std::vector<int> terList;
  Residue* r;
  size_t currentResidueId = 0;
  bool ok(false);
  int coordSet = 0;
  Array<Vector3> positions;

  while (getline(in, buffer)) { // Read Each line one by one

    if (startsWith(buffer, "ENDMDL")) {
      if (coordSet == 0) {
        mol.setCoordinate3d(mol.atomPositions3d(), coordSet++);
        positions.reserve(mol.atomCount());
      } else {
        mol.setCoordinate3d(positions, coordSet++);
        positions.clear();
      }
    }

    else if (startsWith(buffer, "ATOM") || startsWith(buffer, "HETATM")) {
      // First we initialize the residue instance
      size_t residueId = lexicalCast<size_t>(buffer.substr(22, 4), ok);
      if (!ok) {
        appendError("Failed to parse residue sequence number: " +
                    buffer.substr(22, 4));
        return false;
      }

      if (residueId != currentResidueId) {
        currentResidueId = residueId;

        string residueName = lexicalCast<string>(buffer.substr(17, 3), ok);
        if (!ok) {
          appendError("Failed to parse residue name: " + buffer.substr(17, 3));
          return false;
        }

        char chainId = lexicalCast<char>(buffer.substr(21, 1), ok);
        if (!ok) {
          appendError("Failed to parse chain identifier: " +
                      buffer.substr(21, 1));
          return false;
        }

        r = &mol.addResidue(residueName, currentResidueId, chainId);
        if (startsWith(buffer, "HETATM"))
          r->setHeterogen(true);
      }

      string atomName = lexicalCast<string>(buffer.substr(12, 4), ok);
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

      string element; // Element symbol, right justified
      element = buffer.substr(76, 2);
      element = trimmed(element);
      if (element == "SE") // For Sulphur
        element = 'S';

      unsigned char atomicNum = Elements::atomicNumberFromSymbol(element);
      if (atomicNum == 255)
        appendError("Invalid element");

      if (coordSet == 0) {
        Atom newAtom = mol.addAtom(atomicNum);
        newAtom.setPosition3d(pos);
        if (r) {
          r->addResidueAtom(atomName, newAtom);
        }
      } else {
        positions.push_back(pos);
      }
    }

    else if (startsWith(buffer, "TER")) { //  This is very important, each TER
                                          //  record also counts in the serial.
      // Need to account for that when comparing with CONECT
      terList.push_back(lexicalCast<int>(buffer.substr(6, 5), ok));

      if (!ok) {
        appendError("Failed to parse TER serial");
        return false;
      }
    }

    else if (startsWith(buffer, "CONECT")) {
      int a = lexicalCast<int>(buffer.substr(6, 5), ok);
      if (!ok) {
        appendError("Failed to parse coordinate a " + buffer.substr(6, 5));
        return false;
      }
      --a;
      size_t terCount;
      for (terCount = 0; terCount < terList.size() && a > terList[terCount];
           ++terCount)
        ; // semicolon is intentional
      a = a - terCount;

      int bCoords[] = { 11, 16, 21, 26 };
      for (int i = 0; i < 4; i++) {
        if (trimmed(buffer.substr(bCoords[i], 5)) == "")
          break;

        else {
          int b = lexicalCast<int>(buffer.substr(bCoords[i], 5), ok) - 1;
          if (!ok) {
            appendError("Failed to parse coordinate b" + std::to_string(i) +
                        " " + buffer.substr(bCoords[i], 5));
            return false;
          }

          for (terCount = 0; terCount < terList.size() && b > terList[terCount];
               ++terCount)
            ; // semicolon is intentional
          b = b - terCount;

          if (a < b) {
            mol.Avogadro::Core::Molecule::addBond(a, b, 1);
          }
        }
      }
    }
  } // End while loop
  mol.perceiveBondsSimple();
  mol.perceiveBondsFromResidueData();
  return true;
} // End read

std::vector<std::string> PdbFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("pdb");
  return ext;
}

std::vector<std::string> PdbFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("chemical/x-pdb");
  return mime;
}

} // namespace Io
} // namespace Avogadro
