/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "mdlformat.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <iomanip>
#include <iostream>
#include <istream>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Elements;
using Avogadro::Core::lexicalCast;
using Avogadro::Core::Molecule;
using Avogadro::Core::startsWith;
using Avogadro::Core::trimmed;

using std::getline;
using std::istringstream;
using std::setprecision;
using std::setw;
using std::string;

namespace Avogadro::Io {

typedef std::pair<size_t, signed int> chargePair;

MdlFormat::MdlFormat() {}

MdlFormat::~MdlFormat() {}

bool MdlFormat::read(std::istream& in, Core::Molecule& mol)
{
  string buffer;

  // The first line is the molecule name.
  getline(in, buffer);
  buffer = trimmed(buffer);
  // Check for the record separator in SDF, and skip if found.
  if (buffer == "$$$$") {
    getline(in, buffer);
    buffer = trimmed(buffer);
  }
  if (!buffer.empty())
    mol.setData("name", buffer);

  // Skip the next two lines (generator, and comment).
  getline(in, buffer);
  getline(in, buffer);

  // The counts line, and version identifier.
  getline(in, buffer);
  bool ok(false);
  int numAtoms(lexicalCast<int>(buffer.substr(0, 3), ok));
  if (!ok) {
    appendError("Error parsing number of atoms.");
    return false;
  }
  int numBonds(lexicalCast<int>(buffer.substr(3, 3), ok));
  if (!ok) {
    appendError("Error parsing number of bonds.");
    return false;
  }
  string mdlVersion(trimmed(buffer.substr(33)));
  if (mdlVersion != "V2000") {
    appendError("Unsupported file format version encountered: " + mdlVersion);
    return false;
  }

  // Parse the atom block.
  std::vector<chargePair> chargeList;
  for (int i = 0; i < numAtoms; ++i) {
    Vector3 pos;
    getline(in, buffer);
    pos.x() = lexicalCast<Real>(buffer.substr(0, 10), ok);
    if (!ok) {
      appendError("Failed to parse x coordinate: " + buffer.substr(0, 10));
      return false;
    }
    pos.y() = lexicalCast<Real>(buffer.substr(10, 10), ok);
    if (!ok) {
      appendError("Failed to parse y coordinate: " + buffer.substr(10, 10));
      return false;
    }
    pos.z() = lexicalCast<Real>(buffer.substr(20, 10), ok);
    if (!ok) {
      appendError("Failed to parse z coordinate: " + buffer.substr(20, 10));
      return false;
    }

    string element(trimmed(buffer.substr(31, 3)));
    auto charge(lexicalCast<int>(trimmed(buffer.substr(36, 3))));
    if (!buffer.empty()) {
      unsigned char atomicNum = Elements::atomicNumberFromSymbol(element);
      Atom newAtom = mol.addAtom(atomicNum);
      newAtom.setPosition3d(pos);
      // In case there's no CHG property
      charge = (charge > 4) ? ((charge <= 7) ? 4 - charge : 0)
                            : ((charge < 4) ? charge : 0);
      if (charge)
        chargeList.emplace_back(newAtom.index(), charge);
      continue;
    } else {
      appendError("Error parsing atom block: " + buffer);
      return false;
    }
  }

  // Parse the bond block.
  for (int i = 0; i < numBonds; ++i) {
    // Bond atom indices start at 1, -1 for C++.
    getline(in, buffer);
    int begin(lexicalCast<int>(buffer.substr(0, 3), ok) - 1);
    if (!ok) {
      appendError("Error parsing beginning bond index:" + buffer.substr(0, 3));
      return false;
    }
    int end(lexicalCast<int>(buffer.substr(3, 3), ok) - 1);
    if (!ok) {
      appendError("Error parsing end bond index:" + buffer.substr(3, 3));
      return false;
    }
    int order(lexicalCast<int>(buffer.substr(6, 3), ok));
    if (!ok) {
      appendError("Error parsing bond order:" + buffer.substr(6, 3));
      return false;
    }
    if (begin < 0 || begin >= numAtoms || end < 0 || end >= numAtoms) {
      appendError("Bond read in with out of bounds index.");
      return false;
    }
    mol.addBond(mol.atom(begin), mol.atom(end),
                static_cast<unsigned char>(order));
  }

  // Parse the properties block until the end of the file.
  // Property lines count is not used, as it it now unsupported.
  bool foundEnd(false);
  bool foundChgProperty(false);
  while (getline(in, buffer)) {
    string prefix = buffer.substr(0, 6);
    if (prefix == "M  END") {
      foundEnd = true;
      break;
    } else if (prefix == "M  CHG") {
      if (!foundChgProperty)
        chargeList.clear(); // Forget old-style charges
      size_t entryCount(lexicalCast<int>(buffer.substr(6, 3), ok));
      for (size_t i = 0; i < entryCount; i++) {
        size_t index(lexicalCast<size_t>(buffer.substr(10 + 8 * i, 3), ok) - 1);
        if (!ok) {
          appendError("Error parsing charged atom index:" +
                      buffer.substr(10 + 8 * i, 3));
          return false;
        }
        auto charge(lexicalCast<int>(buffer.substr(14 + 8 * i, 3), ok));
        if (!ok) {
          appendError("Error parsing atom charge:" +
                      buffer.substr(14 + 8 * i, 3));
          return false;
        }
        if (charge)
          chargeList.emplace_back(index, charge);
      }
    }
  }

  if (!foundEnd) {
    appendError("Error, ending tag for file not found.");
    return false;
  }

  // Apply charges.
  for (auto & i : chargeList) {
    size_t index = i.first;
    signed int charge = i.second;
    mol.setFormalCharge(index, charge);
  }

  // Check that all atoms were handled.
  if (mol.atomCount() != static_cast<size_t>(numAtoms) ||
      mol.bondCount() != static_cast<size_t>(numBonds)) {
    std::ostringstream errorStream;
    errorStream << "Error parsing file, got " << mol.atomCount()
                << "atoms, expected " << numAtoms << ", got " << mol.bondCount()
                << ", expected " << numBonds << ".";
    appendError(errorStream.str());
    return false;
  }

  // Now parse the data block.
  bool inValue(false);
  string dataName;
  string dataValue;
  while (getline(in, buffer)) {
    if (trimmed(buffer) == "$$$$")
      return true;
    if (inValue) {
      if (buffer.empty() && dataName.length() > 0) {
        mol.setData(dataName, dataValue);
        dataName.clear();
        dataValue.clear();
        inValue = false;
      } else {
        if (dataValue.length())
          dataValue += "\n";
        dataValue += buffer;
      }
    } else if (startsWith(buffer, "> <")) {
      // This is a data header, read the name of the entry, and the value on the
      // following lines.
      dataName = trimmed(buffer).substr(3, buffer.length() - 4);
      inValue = true;
    }
  }

  return true;
}

bool MdlFormat::write(std::ostream& out, const Core::Molecule& mol)
{
  // Header lines.
  out << mol.data("name").toString() << "\n  Avogadro\n\n";
  // Counts line.
  out << setw(3) << std::right << mol.atomCount() << setw(3) << mol.bondCount()
      << "  0  0  0  0  0  0  0  0999 V2000\n";
  // Atom block.
  std::vector<chargePair> chargeList;
  for (size_t i = 0; i < mol.atomCount(); ++i) {
    Atom atom = mol.atom(i);
    signed int charge = atom.formalCharge();
    if (charge)
      chargeList.emplace_back(atom.index(), charge);
    unsigned int chargeField = (charge < 0) ? ((charge >= -3) ? 4 - charge : 0)
                                            : ((charge <= 3) ? charge : 0);
    out << setw(10) << std::right << std::fixed << setprecision(4)
        << atom.position3d().x() << setw(10) << atom.position3d().y()
        << setw(10) << atom.position3d().z() << " " << setw(3) << std::left
        << Elements::symbol(atom.atomicNumber()) << " 0" << setw(3)
        << std::right << chargeField /* for compatibility */
        << "  0  0  0  0  0  0  0  0  0  0\n";
  }
  // Bond block.
  for (size_t i = 0; i < mol.bondCount(); ++i) {
    Bond bond = mol.bond(i);
    out.unsetf(std::ios::floatfield);
    out << setw(3) << std::right << bond.atom1().index() + 1 << setw(3)
        << bond.atom2().index() + 1 << setw(3) << static_cast<int>(bond.order())
        << "  0  0  0  0\n";
  }
  // Properties block.
  for (auto & i : chargeList) {
    Index atomIndex = i.first;
    signed int atomCharge = i.second;
    out << "M  CHG  1 " << setw(3) << std::right << atomIndex + 1 << " "
        << setw(3) << atomCharge << "\n";
  }
  out << "M  END\n";

  if (isMode(FileFormat::MultiMolecule))
    out << "$$$$\n";

  return true;
}

std::vector<std::string> MdlFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.emplace_back("mol");
  ext.emplace_back("sdf");
  return ext;
}

std::vector<std::string> MdlFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.emplace_back("chemical/x-mdl-molfile");
  return mime;
}

} // namespace Avogadro
