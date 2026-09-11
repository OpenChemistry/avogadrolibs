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
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/vector.h>

#include <cctype>
#include <iostream>
#include <istream>
#include <map>
#include <set>
#include <limits>
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
  size_t currentResidueId = std::numeric_limits<size_t>::max();
  char currentChainId = '\0';
  string currentResidueName;
  bool currentHeterogen = false;
  bool ok(false);
  int coordSet = 0;
  Array<Vector3> positions;
  Array<size_t> rawToAtomId;
  Array<size_t> altAtomIds;
  Array<int> altAtomCoordSets;
  Array<char> altAtomLocs;
  std::set<char> altLocs;
  Array<Vector3> altAtomPositions;

  // BIOMT (biological assembly) data
  struct BioMTMatrix
  {
    Eigen::Matrix3d rotation = Eigen::Matrix3d::Identity();
    Vector3 translation = Vector3::Zero();
  };
  struct BioMTGroup
  {
    std::set<char> chains;
    std::vector<BioMTMatrix> matrices;
  };
  auto parseBioMTChains = [](const string& chainStr, std::set<char>& chains) {
    for (char c : chainStr) {
      if (std::isalnum(static_cast<unsigned char>(c)))
        chains.insert(c);
    }
  };
  auto parseBioMTRow = [&](const string& line, int row,
                           BioMTMatrix& mat) -> bool {
    if (line.length() < 68)
      return false;

    bool parseOk = true;
    mat.rotation(row, 0) = lexicalCast<double>(line.substr(24, 9), parseOk);
    if (!parseOk)
      return false;
    mat.rotation(row, 1) = lexicalCast<double>(line.substr(33, 10), parseOk);
    if (!parseOk)
      return false;
    mat.rotation(row, 2) = lexicalCast<double>(line.substr(43, 10), parseOk);
    if (!parseOk)
      return false;
    mat.translation[row] = lexicalCast<double>(line.substr(53, 15), parseOk);
    return parseOk;
  };
  std::vector<BioMTGroup> bioMTGroups;
  BioMTGroup* currentBioMTGroup = nullptr;
  bool inFirstBiomolecule = false;
  bool pastFirstBiomolecule = false;

  while (getline(in, buffer)) { // Read Each line one by one
    if (!in.good())
      break;

    if (startsWith(buffer, "ENDMDL")) {
      // For the first frame (coordSet == 0), positions are stored directly
      // in the molecule, not in the positions array
      if (coordSet == 0) {
        mol.setCoordinate3d(mol.atomPositions3d(), coordSet++);
      } else if (!positions.empty()) {
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

      // Parse space group symbol from columns 56-66
      if (buffer.length() >= 66) {
        std::string spaceGroup = trimmed(buffer.substr(55, 11));
        if (!spaceGroup.empty()) {
          // Tweak PDB space group recognition, e.g. `P 1 21 1` -> `P 1 2_1 1`
          // In each space-separated token, insert '_' between consecutive
          // digits
          for (size_t i = 0; i < spaceGroup.size() - 1; ++i) {
            if (std::isdigit(spaceGroup[i]) &&
                std::isdigit(spaceGroup[i + 1])) {
              spaceGroup.insert(i + 1, 1, '_');
              ++i; // skip past the inserted '_'
            }
          }

          unsigned short hall = Core::SpaceGroups::hallNumber(spaceGroup);
          if (hall > 0)
            mol.setHallNumber(hall);
        }
      }
    }

    // Parse REMARK 350 for biological assembly (BIOMT) matrices
    else if (startsWith(buffer, "REMARK 350") && !pastFirstBiomolecule) {
      if (buffer.find("BIOMOLECULE:") != string::npos) {
        currentBioMTGroup = nullptr;
        if (inFirstBiomolecule) {
          // We've hit a second BIOMOLECULE, stop parsing
          pastFirstBiomolecule = true;
        } else {
          inFirstBiomolecule = true;
        }
      } else if (inFirstBiomolecule &&
                 buffer.find("APPLY THE FOLLOWING TO CHAINS:") !=
                   string::npos) {
        bioMTGroups.emplace_back();
        currentBioMTGroup = &bioMTGroups.back();
        auto colonPos = buffer.find(':');
        if (colonPos != string::npos)
          parseBioMTChains(buffer.substr(colonPos + 1),
                           currentBioMTGroup->chains);
      } else if (inFirstBiomolecule &&
                 buffer.find("AND CHAINS:") != string::npos &&
                 currentBioMTGroup != nullptr) {
        auto colonPos = buffer.find(':');
        if (colonPos != string::npos)
          parseBioMTChains(buffer.substr(colonPos + 1),
                           currentBioMTGroup->chains);
      } else if (inFirstBiomolecule && buffer.find("BIOMT1") != string::npos &&
                 currentBioMTGroup != nullptr) {
        currentBioMTGroup->matrices.emplace_back();
        parseBioMTRow(buffer, 0, currentBioMTGroup->matrices.back());
      } else if (inFirstBiomolecule && buffer.find("BIOMT2") != string::npos &&
                 currentBioMTGroup != nullptr &&
                 !currentBioMTGroup->matrices.empty()) {
        parseBioMTRow(buffer, 1, currentBioMTGroup->matrices.back());
      } else if (inFirstBiomolecule && buffer.find("BIOMT3") != string::npos &&
                 currentBioMTGroup != nullptr &&
                 !currentBioMTGroup->matrices.empty()) {
        parseBioMTRow(buffer, 2, currentBioMTGroup->matrices.back());
      }
    }

    else if (startsWith(buffer, "ATOM") || startsWith(buffer, "HETATM")) {
      if (buffer.length() < 54) {
        appendError("Error reading line.");
        return false;
      }

      const bool isHeterogen = startsWith(buffer, "HETATM");

      // First we initialize the residue instance
      auto residueId = lexicalCast<size_t>(buffer.substr(22, 4), ok);
      if (!ok) {
        appendError("Failed to parse residue sequence number: " +
                    buffer.substr(22, 4));
        return false;
      }

      auto residueName = lexicalCast<string>(buffer.substr(17, 3), ok);
      if (!ok) {
        appendError("Failed to parse residue name: " + buffer.substr(17, 3));
        return false;
      }

      char chainId = lexicalCast<char>(buffer.substr(21, 1), ok);
      if (!ok) {
        chainId = 'A'; // it's a non-standard "PDB"-like file
      }

      if (residueId != currentResidueId || chainId != currentChainId ||
          residueName != currentResidueName ||
          isHeterogen != currentHeterogen) {
        currentResidueId = residueId;
        currentChainId = chainId;
        currentResidueName = residueName;
        currentHeterogen = isHeterogen;
        r = &mol.addResidue(residueName, currentResidueId, chainId);
        if (isHeterogen)
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

        // Not an error yet: older files put other things in these columns,
        // and the atom name below still has two chances to identify the
        // element. Only the final failure is worth reporting.
        atomicNum = Elements::atomicNumberFromSymbol(element);
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
      }

      if (atomicNum == 255) {
        // Fall back to the column convention for the atom name, which is what
        // pre-2000 files need: columns 77-78 only became the element field
        // later, and older files put other things there (1CRN.pdb keeps a
        // line serial, so every record above lands here).
        //
        // Columns 13-16 hold the atom name with the element symbol right
        // justified in 13-14. A one-character symbol therefore leaves column
        // 13 blank -- " CA " is a carbon alpha, not calcium -- while a
        // two-character symbol fills both columns, as in "FE  " or "ZN  ".
        // Hydrogens may carry a number in column 13, as in "1HB ". Reading
        // the two cases apart is the whole point of the convention, and it is
        // why the naive "treat the trimmed name as a symbol" attempt above
        // drops every CA, CB, SG and OG in a protein.
        const std::string rawName = buffer.substr(12, 4);
        const auto first = static_cast<unsigned char>(rawName[0]);
        std::string symbol;
        if (first == ' ' || std::isdigit(first) != 0) {
          symbol = rawName.substr(1, 1);
        } else {
          // Column 13 is occupied, so try both characters as a symbol before
          // falling back to the first alone.
          std::string twoChar;
          twoChar += static_cast<char>(std::toupper(first));
          twoChar += static_cast<char>(
            std::tolower(static_cast<unsigned char>(rawName[1])));
          symbol = (Elements::atomicNumberFromSymbol(twoChar) != 255)
                     ? twoChar
                     : rawName.substr(0, 1);
        }
        symbol = trimmed(symbol);
        if (!symbol.empty()) {
          symbol[0] = static_cast<char>(
            std::toupper(static_cast<unsigned char>(symbol[0])));
          atomicNum = Elements::atomicNumberFromSymbol(symbol);
          // "Xx" is the dummy-atom symbol and would match a name such as
          // "XX", quietly inventing a placeholder atom. A name this fallback
          // cannot read should stay unread.
          if (atomicNum == 0)
            atomicNum = 255;
        }
      }

      if (atomicNum == 255) {
        appendError("Invalid element");
        // Still claim this record's slot in the serial-number mapping.
        // CONECT records index rawToAtomId by (serial - 1 - TER count), so a
        // skipped record that pushes nothing shifts every later serial and
        // silently bonds the wrong pair of atoms. Only coordSet 0 builds the
        // mapping, matching the push sites below.
        if (coordSet == 0)
          rawToAtomId.push_back(MaxIndex);
        continue; // skip this invalid record
      }

      if (altLoc.compare("") && altLoc.compare("A")) {
        if (coordSet == 0) {
          rawToAtomId.push_back(MaxIndex);
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

      // Resolve a serial number, as adjusted above, to the atom it names.
      // The value comes straight out of the file, so it has to be range
      // checked before it is used as an index: PDB files routinely arrive
      // over the network, and a serial past the end of the mapping (from a
      // truncated, hand-edited or hostile file) would otherwise read out of
      // bounds. MaxIndex marks a record that was read but produced no atom.
      auto resolveSerial = [&rawToAtomId](int raw, Index& atomId) {
        if (raw < 0 || static_cast<size_t>(raw) >= rawToAtomId.size())
          return false;
        const size_t mapped = rawToAtomId[static_cast<size_t>(raw)];
        if (mapped == MaxIndex)
          return false;
        atomId = mapped;
        return true;
      };

      Index aIndex = MaxIndex;
      if (!resolveSerial(a, aIndex)) {
        appendError("Ignoring CONECT record for unknown atom serial " +
                    buffer.substr(6, 5));
        continue;
      }

      int bCoords[] = { 11, 16, 21, 26 };
      for (int i = 0; i < 4; i++) {
        // Check if buffer is long enough for this column
        if (static_cast<int>(buffer.length()) < bCoords[i] + 5)
          break;
        if (trimmed(buffer.substr(bCoords[i], 5)).empty())
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

          Index bIndex = MaxIndex;
          if (!resolveSerial(b, bIndex)) {
            appendError("Ignoring CONECT bond to unknown atom serial " +
                        buffer.substr(bCoords[i], 5));
            continue;
          }

          if (aIndex < mol.atomCount() && bIndex < mol.atomCount()) {
            mol.addBond(aIndex, bIndex, 1);
          } else {
            appendError("Invalid bond connection: " + std::to_string(aIndex) +
                        " - " + std::to_string(bIndex));
          }
        }
      }
    }
  } // End while loop

  if (mol.atomCount() == 0) {
    appendError("No atoms found in this file.");
    return false;
  }

  if (!positions.empty()) {
    // This handles the last set of positions if the file doesn't end with
    // ENDMDL
    mol.setCoordinate3d(positions, coordSet);
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

  // Apply BIOMT matrices to generate biological assembly
  if (!bioMTGroups.empty()) {
    const Index originalAtomCount = mol.atomCount();
    const Index originalBondCount = mol.bondCount();
    const Index originalResidueCount = mol.residueCount();
    const Array<Vector3> originalPositions = mol.atomPositions3d();

    struct CoordinateSetInfo
    {
      size_t index;
      Array<Vector3> source;
      Array<Vector3> expanded;
    };
    std::vector<CoordinateSetInfo> coordinateSets;
    coordinateSets.reserve(mol.coordinate3dCount());
    for (size_t ci = 0; ci < mol.coordinate3dCount(); ++ci) {
      Array<Vector3> coords = mol.coordinate3d(ci);
      if (coords.size() != originalAtomCount)
        continue;

      coordinateSets.push_back({ ci, coords, coords });
    }

    struct BondInfo
    {
      Index atom1, atom2;
      unsigned char order;
    };

    struct ResidueInfo
    {
      std::string name;
      Index id;
      char chainId;
      bool heterogen;
      Residue::SecondaryStructure ss;
      std::vector<std::pair<std::string, Index>> atomNames; // name, orig index
    };

    for (const auto& group : bioMTGroups) {
      if (group.chains.empty() || group.matrices.empty())
        continue;

      std::vector<Index> assemblyAtoms;
      std::set<Index> assemblySet;
      std::vector<ResidueInfo> residuesToCopy;

      for (Index ri = 0; ri < originalResidueCount; ++ri) {
        const auto& origRes = mol.residue(ri);
        if (!group.chains.count(origRes.chainId()))
          continue;

        ResidueInfo info;
        info.name = origRes.residueName();
        info.id = origRes.residueId();
        info.chainId = origRes.chainId();
        info.heterogen = origRes.isHeterogen();
        info.ss = origRes.secondaryStructure();
        for (const auto& atom : origRes.residueAtoms()) {
          if (assemblySet.insert(atom.index()).second)
            assemblyAtoms.push_back(atom.index());

          std::string aName = origRes.atomName(atom);
          if (!aName.empty())
            info.atomNames.emplace_back(aName, atom.index());
        }
        residuesToCopy.push_back(std::move(info));
      }

      if (assemblyAtoms.empty())
        continue;

      std::vector<BondInfo> assemblyBonds;
      for (Index bi = 0; bi < originalBondCount; ++bi) {
        auto bp = mol.bondPair(bi);
        if (assemblySet.count(bp.first) && assemblySet.count(bp.second)) {
          assemblyBonds.push_back({ bp.first, bp.second, mol.bondOrder(bi) });
        }
      }

      for (const auto& mat : group.matrices) {
        if (mat.rotation.isIdentity(1e-6) && mat.translation.norm() < 1e-6) {
          continue;
        }

        std::map<Index, Index> oldToNew;

        for (Index origIdx : assemblyAtoms) {
          Vector3 transformed =
            mat.rotation * originalPositions[origIdx] + mat.translation;
          Atom newAtom = mol.addAtom(mol.atomicNumber(origIdx), transformed);
          if (mol.formalCharge(origIdx) != 0)
            mol.setFormalCharge(newAtom.index(), mol.formalCharge(origIdx));
          if (mol.isotope(origIdx) != 0)
            mol.setIsotope(newAtom.index(), mol.isotope(origIdx));
          oldToNew[origIdx] = newAtom.index();

          for (auto& coordSet : coordinateSets) {
            coordSet.expanded.push_back(
              mat.rotation * coordSet.source[origIdx] + mat.translation);
          }
        }

        for (const auto& bond : assemblyBonds) {
          auto it1 = oldToNew.find(bond.atom1);
          auto it2 = oldToNew.find(bond.atom2);
          if (it1 != oldToNew.end() && it2 != oldToNew.end())
            mol.addBond(it1->second, it2->second, bond.order);
        }

        for (const auto& info : residuesToCopy) {
          std::string resName = info.name;
          Index resId = info.id;
          char chainId = info.chainId;
          auto& newRes = mol.addResidue(resName, resId, chainId);
          newRes.setHeterogen(info.heterogen);
          newRes.setSecondaryStructure(info.ss);
          for (const auto& pair : info.atomNames) {
            auto it = oldToNew.find(pair.second);
            if (it != oldToNew.end())
              newRes.addResidueAtom(pair.first, mol.atom(it->second));
          }
        }
      }
    }

    for (const auto& coordSet : coordinateSets)
      mol.setCoordinate3d(coordSet.expanded, coordSet.index);
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
