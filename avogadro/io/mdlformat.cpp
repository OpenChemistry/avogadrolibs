/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "mdlformat.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <chrono>
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
using Avogadro::Core::endsWith;
using Avogadro::Core::lexicalCast;
using Avogadro::Core::split;
using Avogadro::Core::startsWith;
using Avogadro::Core::trimmed;

using std::getline;
using std::istringstream;
using std::setprecision;
using std::setw;
using std::string;

namespace Avogadro::Io {

using chargePair = std::pair<size_t, int>;
namespace {

// Helper function to handle partial charge property blocks
// e.g. PUBCHEM_MMFF94_PARTIAL_CHARGES
void handlePartialCharges(Core::Molecule& mol, std::string data,
                          std::string name = "MMFF94")
{
  // the string starts with the number of charges
  // then atom index  charge
  MatrixX charges(mol.atomCount(), 1);
  std::istringstream iss(data);
  size_t numCharges;
  iss >> numCharges;
  if (numCharges == 0 || numCharges > mol.atomCount()) {
    return;
  }

  for (size_t i = 0; i < numCharges; ++i) {
    if (!iss.good()) {
      return;
    }

    size_t index = 0;
    Real charge = 0.0;

    iss >> index;
    if (iss.fail() || index == 0 || index > mol.atomCount()) {
      return;
    }

    iss >> charge;
    if (iss.fail()) {
      return;
    }
    // prints with atom index 1, not zero
    charges(index - 1, 0) = charge;
  }

  // if present, remove atom.dpos and CHARGES from the string
  if (startsWith(name, "atom.dpos")) {
    name = name.substr(9, name.size() - 16);
  }
  if (endsWith(name, "CHARGES")) {
    name = name.substr(0, name.size() - 7);
  }

  mol.setPartialCharges(name, charges);
}
} // namespace

bool MdlFormat::read(std::istream& in, Core::Molecule& mol)
{
  string buffer;
  int spinMultiplicity = 1; // check for RAD lines

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

  if (!in.good()) {
    appendError("Error reading molecule name.");
    return false;
  }

  // Skip the next two lines (generator, and comment).
  getline(in, buffer);
  getline(in, buffer);
  if (!in.good()) {
    appendError("Error reading generator and comment lines.");
    return false;
  }

  // The counts line, and version identifier.
  getline(in, buffer);
  // should be long enough, e.g.
  //   5  4  0  0  0  0  0  0  0  0999 V2000
  if (!in.good() || buffer.size() < 39) {
    appendError("Error reading counts line.");
    return false;
  }

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
  if (mdlVersion == "V3000")
    return readV3000(in, mol);
  else if (mdlVersion != "V2000") {
    appendError("Unsupported MDL version: " + mdlVersion);
    return false;
  }

  // Parse the atom block.
  std::vector<chargePair> chargeList;
  for (int i = 0; i < numAtoms; ++i) {
    Vector3 pos;
    getline(in, buffer);
    //     0.0000    0.0000    0.0000 C   0  0  0  0  0  0  0  0  0  0  0  0
    if (!in.good() || buffer.size() < 40) {
      appendError("Error reading atom block.");
      return false;
    }

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
    auto charge(lexicalCast<int>(trimmed(buffer.substr(36, 3))).value_or(0));
    if (!buffer.empty()) {
      unsigned char atomicNum = Elements::atomicNumberFromSymbol(element);
      Atom newAtom = mol.addAtom(atomicNum);
      newAtom.setPosition3d(pos);
      // In case there's no CHG property
      if (charge == 4) // doublet radical
        spinMultiplicity += 1;

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
    //   1  2  1  0  0  0  0
    if (!in.good() || buffer.size() < 10) {
      appendError("Error reading bond block.");
      return false;
    }

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
    if (!in.good() || buffer.size() < 6) {
      break;
    }

    string prefix = buffer.substr(0, 6);
    if (prefix == "M  END") {
      foundEnd = true;
      break;
    } else if (prefix == "M  CHG") {
      if (!foundChgProperty)
        chargeList.clear(); // Forget old-style charges
      size_t entryCount(lexicalCast<int>(buffer.substr(6, 3), ok));
      if (buffer.length() < 17 + 8 * (entryCount - 1)) {
        appendError("Error parsing charge block.");
        std::cout << " " << entryCount << " " << buffer.length() << std::endl;
        return false;
      }

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
    } else if (prefix == "M  RAD") {
      // radical center
      spinMultiplicity = 1; // reset and count
      size_t entryCount(lexicalCast<int>(buffer.substr(6, 3), ok));
      if (buffer.length() < 17 + 8 * (entryCount - 1)) {
        appendError("Error parsing radical block.");
        return false;
      }

      for (size_t i = 0; i < entryCount; i++) {
        [[maybe_unused]] size_t index(
          lexicalCast<size_t>(buffer.substr(10 + 8 * i, 3), ok) - 1);
        if (!ok) {
          appendError("Error parsing radical atom index:" +
                      buffer.substr(10 + 8 * i, 3));
          return false;
        }
        auto radical(lexicalCast<int>(buffer.substr(14 + 8 * i, 3), ok));
        if (!ok) {
          appendError("Error parsing radical type:" +
                      buffer.substr(14 + 8 * i, 3));
          return false;
        }
        // we don't set radical centers, just count them
        // for the total spin multiplicity
        if (radical == 2) // doublet
          spinMultiplicity += 1;
        else if (radical == 3) // triplet
          spinMultiplicity += 2;
      }
    } else if (prefix == "M  ISO") {
      // isotope
      size_t entryCount(lexicalCast<int>(buffer.substr(6, 3), ok));
      if (buffer.length() < 17 + 8 * (entryCount - 1)) {
        appendError("Error parsing isotope block.");
        return false;
      }

      for (size_t i = 0; i < entryCount; i++) {
        [[maybe_unused]] size_t index(
          lexicalCast<size_t>(buffer.substr(10 + 8 * i, 3), ok) - 1);
        if (!ok) {
          appendError("Error parsing isotope atom index:" +
                      buffer.substr(10 + 8 * i, 3));
          return false;
        }
        [[maybe_unused]] auto isotope(
          lexicalCast<int>(buffer.substr(14 + 8 * i, 3), ok));
        if (!ok) {
          appendError("Error parsing isotope type:" +
                      buffer.substr(14 + 8 * i, 3));
          return false;
        }
        // TODO: Implement isotope setting
        // mol.atom(index).setIsotope(isotope);
      }
    } // isotope
    else {
#ifndef NDEBUG
      std::cout << " prefix " << buffer.substr(0, 6) << std::endl;
#endif
    }
  }

  if (!foundEnd) {
    appendError("Error, ending tag for file not found.");
    return false;
  }

  // Apply charges.
  for (auto& i : chargeList) {
    size_t index = i.first;
    signed int charge = i.second;
    mol.setFormalCharge(index, charge);
  }

  // Set the total spin multiplicity
  if (spinMultiplicity > 1)
    mol.setData("totalSpinMultiplicity", spinMultiplicity);

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
  while (getline(in, buffer) && in.good()) {
    if (trimmed(buffer) == "$$$$")
      break;
    if (inValue) {
      if (buffer.empty() && dataName.length() > 0) {
        // check for partial charges
        if (dataName == "PUBCHEM_MMFF94_PARTIAL_CHARGES")
          handlePartialCharges(mol, dataValue);
        else if (startsWith(dataName, "atom.dpos") &&
                 endsWith(dataName, "CHARGES"))
          // remove the "CHARGES" from the end of the string
          handlePartialCharges(mol, dataValue, dataName);
        else
          mol.setData(dataName, dataValue);

        dataName.clear();
        dataValue.clear();
        inValue = false;
      } else {
        if (dataValue.length())
          dataValue += "\n";
        dataValue += buffer;
      }
    } else if (startsWith(buffer, "> ")) {
      // This is a data header, read the name of the entry, and the value on
      // the following lines.
      // e.g., > <propName>
      // dataName will be anything from < to >
      size_t start = buffer.find('<');
      size_t end = buffer.find('>', start);
      if (start != string::npos && end != string::npos) {
        dataName = buffer.substr(start + 1, end - start - 1);
        inValue = true;
      }
    }
  }

  // handle pKa from QupKake model
  if (mol.hasData("pka") && mol.hasData("idx")) {
    // pka can sometimes say "tensor(3.1452)" or "3.1452"
    // just convert to a string with 2 decimal places
    std::string pka = mol.data("pka").toString();
    if (startsWith(pka, "tensor("))
      pka = pka.substr(7, pka.size() - 8);
    // find the decimal to only keep 2 decimal places
    size_t decimal = pka.find(".");
    if (decimal != std::string::npos)
      pka = pka.substr(0, decimal + 3);
    mol.setData("pka", pka);
    // convert the idx to an atom index
    // and set the label
    std::string idx = mol.data("idx").toString();
    size_t atomIdx = lexicalCast<size_t>(idx).value_or(0);
    mol.setAtomLabel(atomIdx, pka);
  }

  return true;
}

bool MdlFormat::readV3000(std::istream& in, Core::Molecule& mol)
{
  string buffer;
  int spinMultiplicity = 1; // check for RAD lines
  // we should have M  V30 BEGIN CTAB
  getline(in, buffer);
  if (trimmed(buffer) != "M  V30 BEGIN CTAB") {
    appendError("Error parsing V3000 file, expected 'M  V30 BEGIN CTAB'.");
    return false;
  }
  // now we should get the counts line
  // e.g. 'M  V30 COUNTS 23694 24297 0 0 1'
  getline(in, buffer);
  // split by whitespace
  std::vector<string> counts = split(trimmed(buffer), ' ');
  if (counts.size() < 5) {
    appendError("Error parsing V3000 counts line.");
    return false;
  }
  bool ok(false);
  int numAtoms(lexicalCast<int>(counts[3], ok));
  if (!ok) {
    appendError("Error parsing number of atoms.");
    return false;
  }
  int numBonds(lexicalCast<int>(counts[4], ok));
  if (!ok) {
    appendError("Error parsing number of bonds.");
    return false;
  }

  // Parse the atom block.
  // 'M  V30 BEGIN ATOM'
  // 'M  V30 1 N 171.646 251.874 224.877 0'
  getline(in, buffer);
  if (trimmed(buffer) != "M  V30 BEGIN ATOM") {
    appendError("Error parsing V3000 atom block.");
    return false;
  }
  for (int i = 0; i < numAtoms; ++i) {
    getline(in, buffer);
    std::vector<string> atomData = split(trimmed(buffer), ' ');
    if (atomData.size() < 7) {
      appendError("Error parsing V3000 atom line.");
      return false;
    }

    string element(trimmed(atomData[3]));
    unsigned char atomicNum = Elements::atomicNumberFromSymbol(element);
    Atom newAtom = mol.addAtom(atomicNum);

    Vector3 pos;
    pos.x() = lexicalCast<Real>(atomData[4], ok);
    if (!ok) {
      appendError("Failed to parse x coordinate: " + atomData[3]);
      return false;
    }
    pos.y() = lexicalCast<Real>(atomData[5], ok);
    if (!ok) {
      appendError("Failed to parse y coordinate: " + atomData[4]);
      return false;
    }
    pos.z() = lexicalCast<Real>(atomData[6], ok);
    if (!ok) {
      appendError("Failed to parse z coordinate: " + atomData[5]);
      return false;
    }
    newAtom.setPosition3d(pos);
    // check for formal charge in the atom block
    // CHG=1 for example
    if (atomData.size() > 8) {
      // loop through the key=value pairs
      for (size_t j = 8; j < atomData.size(); ++j) {
        string key = atomData[j];
        if (startsWith(key, "CHG=")) {
          int charge = lexicalCast<int>(key.substr(4), ok);
          if (!ok) {
            appendError("Failed to parse atom charge: " + key);
            return false;
          }
          newAtom.setFormalCharge(charge);
        } else if (startsWith(key, "RAD=")) {
          // radical center
          int radical = lexicalCast<int>(key.substr(4), ok);
          if (!ok) {
            appendError("Failed to parse radical type: " + key);
            return false;
          }
          // we don't set radical centers, just count them
          // for the total spin multiplicity
          if (radical == 2) // doublet
            spinMultiplicity += 1;
          else if (radical == 3) // triplet
            spinMultiplicity += 2;
        } else if (startsWith(key, "ISO=")) {
          // isotope
          [[maybe_unused]] int isotope = lexicalCast<int>(key.substr(4), ok);
          if (!ok) {
            appendError("Failed to parse isotope type: " + key);
            return false;
          }
          // TODO: handle isotopes
          // mol.atom(i).setIsotope(isotope);
        } else {
#ifndef NDEBUG
          std::cerr << "Unknown key: " << key << std::endl;
#endif
        }
      } // end of key-value loop
    }
  } // end of atom block
  getline(in, buffer);
  // check for END ATOM
  if (trimmed(buffer) != "M  V30 END ATOM") {
    appendError("Error parsing V3000 atom block.");
    return false;
  }

  // bond block
  // 'M  V30 BEGIN BOND'
  // 'M  V30 1 1 1 2'
  getline(in, buffer);
  if (trimmed(buffer) != "M  V30 BEGIN BOND") {
    appendError("Error parsing V3000 bond block.");
    return false;
  }
  for (int i = 0; i < numBonds; ++i) {
    getline(in, buffer);
    std::vector<string> bondData = split(trimmed(buffer), ' ');
    if (bondData.size() < 5) {
      appendError("Error parsing V3000 bond line.");
      return false;
    }
    int order = lexicalCast<int>(bondData[3], ok);
    if (!ok) {
      appendError("Failed to parse bond order: " + bondData[3]);
      return false;
    }
    int atom1 = lexicalCast<int>(bondData[4], ok) - 1;
    if (!ok) {
      appendError("Failed to parse bond atom1: " + bondData[4]);
      return false;
    }
    int atom2 = lexicalCast<int>(bondData[5], ok) - 1;
    if (!ok) {
      appendError("Failed to parse bond atom2: " + bondData[5]);
      return false;
    }
    mol.addBond(mol.atom(atom1), mol.atom(atom2),
                static_cast<unsigned char>(order));
  } // end of bond block

  // look for M  END
  while (getline(in, buffer)) {
    if (trimmed(buffer) == "M  END")
      break;
  }
  // read in any properties
  while (getline(in, buffer)) {
    if (startsWith(buffer, "> <")) {
      string key = trimmed(buffer.substr(3, buffer.length() - 4));
      string value;
      while (getline(in, buffer)) {
        if (trimmed(buffer) == "")
          break;
        value += buffer + "\n";
      }
      mol.setData(key, value);
    }
  }

  // if we have a spin multiplicity, set it
  if (spinMultiplicity > 1)
    mol.setData("totalSpinMultiplicity", spinMultiplicity);

  return true;
}

bool MdlFormat::writeV3000(std::ostream& out, const Core::Molecule& mol)
{
  // write the "fake" counts line
  out << "  0  0  0     0  0            999 V3000\n";
  out << "M  V30 BEGIN CTAB\n";
  out << "M  V30 COUNTS " << mol.atomCount() << ' ' << mol.bondCount()
      << " 0 0 0\n";
  // atom block
  out << "M  V30 BEGIN ATOM\n";
  for (size_t i = 0; i < mol.atomCount(); ++i) {
    Atom atom = mol.atom(i);
    out << "M  V30 " << i + 1 << ' ' << Elements::symbol(atom.atomicNumber())
        << ' ' << atom.position3d().x() << ' ' << atom.position3d().y() << ' '
        << atom.position3d().z() << " 0";
    if (atom.formalCharge())
      out << " CHG=" << atom.formalCharge();
    out << "\n";
  }
  out << "M  V30 END ATOM\n";
  // bond block
  out << "M  V30 BEGIN BOND\n";
  for (size_t i = 0; i < mol.bondCount(); ++i) {
    Bond bond = mol.bond(i);
    out << "M  V30 " << i + 1 << ' ' << static_cast<int>(bond.order()) << ' '
        << (bond.atom1().index() + 1) << ' ' << (bond.atom2().index() + 1)
        << " \n";
  }
  out << "M  V30 END BOND\n";
  out << "M  V30 END CTAB\n";
  out << "M  END\n";

  // TODO: isotopes, radicals, etc.
  if (m_writeProperties) {
    const auto dataMap = mol.dataMap();
    for (const auto& key : dataMap.names()) {
      // skip some keys
      if (key == "modelView" || key == "projection")
        continue;

      out << "> <" << key << ">\n";
      out << dataMap.value(key).toString() << "\n";
      out << "\n"; // empty line between data blocks
    }
  }

  if (m_writeProperties || isMode(FileFormat::MultiMolecule))
    out << "$$$$\n";

  return true;
}

bool MdlFormat::write(std::ostream& out, const Core::Molecule& mol)
{
  // Header lines.
  out << mol.data("name").toString() << "\n";

  // Mol block header - need to indicate 3D coords
  // e.g.   Avogadro08072512293D
  // name of program MMDDYYHM3D
  auto now = std::chrono::system_clock::now();
  // Convert to time_t for use with ctime functions
  std::time_t time_t_now = std::chrono::system_clock::to_time_t(now);
  // Convert to a local time structure (tm)
  std::tm* local_time = std::localtime(&time_t_now);

  // Format the time using std::put_time
  // %m: Month as decimal number (01-12)
  // %d: Day of the month as decimal number (01-31)
  // %y: Year without century (00-99)
  // %H: Hour in 24-hour format (00-23)
  // %M: Minute as decimal number (00-59)
  out << "  Avogadro" << std::put_time(local_time, "%m%d%y%H%M") << "3D\n\n";

  // Counts line.
  if (mol.atomCount() > 999 || mol.bondCount() > 999) {
    // we need V3000 support for big molecules
    return writeV3000(out, mol);
  }

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
        << setw(10) << atom.position3d().z() << ' ' << setw(3) << std::left
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
  for (auto& i : chargeList) {
    Index atomIndex = i.first;
    signed int atomCharge = i.second;
    out << "M  CHG  1 " << setw(3) << std::right << atomIndex + 1 << ' '
        << setw(3) << atomCharge << "\n";
  }
  // TODO: isotopes, etc.
  out << "M  END\n";
  // Data block
  if (m_writeProperties) {
    const auto dataMap = mol.dataMap();
    for (const auto& key : dataMap.names()) {
      // skip some keys
      if (key == "modelView" || key == "projection")
        continue;

      out << "> <" << key << ">\n";
      out << dataMap.value(key).toString() << "\n";
      out << "\n"; // empty line between data blocks
    }
  }

  if (m_writeProperties || isMode(FileFormat::MultiMolecule))
    out << "$$$$\n";

  return true;
}

std::vector<std::string> MdlFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.emplace_back("mol");
  return ext;
}

std::vector<std::string> MdlFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.emplace_back("chemical/x-mdl-molfile");
  return mime;
}

} // namespace Avogadro::Io
