/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "mmtfformat.h"
#include <avogadro/core/array.h>
#include <avogadro/core/crystaltools.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>

#include <mmtf.hpp>

#include <iomanip>
#include <iostream>

namespace Avogadro::Io {

using std::string;
using std::vector;

using Core::Array;
using Core::Elements;
using Core::lexicalCast;
using Core::Molecule;
using Core::Residue;

MMTFFormat::MMTFFormat() = default;

MMTFFormat::~MMTFFormat() = default;

// from latest MMTF code, under the MIT license
// https://github.com/rcsb/mmtf-cpp/blob/master/include/mmtf/structure_data.hpp
bool is_polymer(const unsigned int chain_index,
                const std::vector<mmtf::Entity>& entity_list)
{
  for (const auto & i : entity_list) {
    if (std::find(i.chainIndexList.begin(),
                  i.chainIndexList.end(),
                  chain_index) != i.chainIndexList.end()) {
      return (i.type == "polymer" ||
              i.type == "POLYMER");
    }
  }
  return false;
}

bool MMTFFormat::read(std::istream& file, Molecule& molecule)
{
  mmtf::StructureData structure;
  mmtf::decodeFromStream(structure, file);

  // This controls which model we load, currently just the first?
  size_t modelIndex = 0;
  size_t atomSkip = 0;

  size_t chainIndex = 0;
  size_t groupIndex = 0;
  size_t atomIndex = 0;

  molecule.setData("name", structure.title);

  if (structure.unitCell.size() == 6) {
    Real a = static_cast<Real>(structure.unitCell[0]);
    Real b = static_cast<Real>(structure.unitCell[1]);
    Real c = static_cast<Real>(structure.unitCell[2]);
    Real alpha = static_cast<Real>(structure.unitCell[3]) * DEG_TO_RAD;
    Real beta = static_cast<Real>(structure.unitCell[4]) * DEG_TO_RAD;
    Real gamma = static_cast<Real>(structure.unitCell[5]) * DEG_TO_RAD;

    auto* unitCellObject =
      new Core::UnitCell(a, b, c, alpha, beta, gamma);
    molecule.setUnitCell(unitCellObject);
  }
  // spaceGroup
  if (structure.spaceGroup.size() > 0) {
    unsigned short hall = 0;
    hall = Core::SpaceGroups::hallNumber(structure.spaceGroup);

    if (hall != 0) {
      molecule.setHallNumber(hall);
    }
  }

  auto modelChainCount =
    static_cast<Index>(structure.chainsPerModel[modelIndex]);

  auto entityList = structure.entityList;
  auto secStructList = structure.secStructList;

  Array<size_t> rawToAtomId;
  Array<size_t> altAtomIds;
  Array<int> altAtomCoordSets;
  Array<char> altAtomLocs;
  std::set<char> altLocs;
  Array<Vector3> altAtomPositions;

  for (Index j = 0; j < modelChainCount; j++) {

    auto chainGroupCount =
      static_cast<Index>(structure.groupsPerChain[chainIndex]);

    bool ok;
    std::string chainid_string = structure.chainIdList[chainIndex];
    char chainid = lexicalCast<char>(chainid_string.substr(0, 1), ok);

    bool isPolymer = is_polymer(chainIndex, entityList);

    // A group is like a residue or other molecule in a PDB file.
    for (size_t k = 0; k < chainGroupCount; k++) {

      auto groupType = static_cast<Index>(structure.groupTypeList[groupIndex]);

      const auto& group = structure.groupList[groupType];

      auto groupId = static_cast<Index>(structure.groupIdList[groupIndex]);
      auto resname = group.groupName;

      auto& residue = molecule.addResidue(resname, groupId, chainid);
      // Stores if the group / residue is a heterogen
      //
      if (!isPolymer || mmtf::is_hetatm(group.chemCompType.c_str()))
        residue.setHeterogen(true);

      // Unfortunately, while the spec says secondary structure
      // is (optionally) in groups, the code doesn't make it available.
      // group.secStruct is a binary type
      // https://github.com/rcsb/mmtf/blob/master/spec.md#secstructlist
      // 0 = pi helix, 1 = bend, 2 = alpha helix, 3 = extended beta, 4 = 3-10
      // helix, etc.
      // residue.setSecondaryStructure(group.secStruct);
      //
      // instead, we'll get it from secStructList
      auto secStructure = structure.secStructList[groupIndex];
      residue.setSecondaryStructure(
        static_cast<Avogadro::Core::Residue::SecondaryStructure>(secStructure));

      // Save the offset before we go changing it
      Index atomOffset = atomIndex - atomSkip;
      Index groupSize = group.atomNameList.size();

      for (Index l = 0; l < groupSize; l++) {
        Vector3 pos(static_cast<Real>(structure.xCoordList[atomIndex]),
                  static_cast<Real>(structure.yCoordList[atomIndex]),
                  static_cast<Real>(structure.zCoordList[atomIndex]));
        if (structure.altLocList[atomIndex] != '\0' && structure.altLocList[atomIndex] != 'A') {
          rawToAtomId.push_back(-1);
          altAtomIds.push_back(molecule.atomCount() - 1);
          altAtomLocs.push_back(structure.altLocList[atomIndex]);
          altLocs.insert(structure.altLocList[atomIndex]);
          altAtomPositions.push_back(pos);
          atomIndex++;
          continue;
        }

        auto atom = molecule.addAtom(
          Elements::atomicNumberFromSymbol(group.elementList[l]));

        atom.setFormalCharge(group.formalChargeList[l]);
        atom.setPosition3d(pos);

        std::string atomName = group.atomNameList[l];
        residue.addResidueAtom(atomName, atom);
        rawToAtomId.push_back(molecule.atomCount() - 1);
        atomIndex++;
      }

      // Intra-residue bonds
      for (size_t l = 0; l < group.bondOrderList.size(); l++) {

        auto atom1 = static_cast<Index>(rawToAtomId[atomOffset + group.bondAtomList[l * 2]]);
        auto atom2 = static_cast<Index>(rawToAtomId[atomOffset + group.bondAtomList[l * 2 + 1]]);

        char bo = static_cast<char>(group.bondOrderList[l]);

        if (atom1 < molecule.atomCount() && atom2 < molecule.atomCount())
          molecule.addBond(atom1, atom2, bo);
      }

      // This is the original PDB Chain name
      // if (!structure_.chainNameList.empty()) {
      //  structure.chainNameList[chainIndex_];
      //}

      groupIndex++;
    }

    chainIndex++;
  }

  // Use this eventually for multi-model formats
  modelIndex++;

  // These are for inter-residue bonds
  for (size_t i = 0; i < structure.bondAtomList.size() / 2; i++) {

    auto atom1 = static_cast<size_t>(rawToAtomId[structure.bondAtomList[i * 2]]);
    auto atom2 = static_cast<size_t>(rawToAtomId[structure.bondAtomList[i * 2 + 1]]);

    /* Code for multiple models
    // We are below the atoms we care about
    if (atom1 < atomSkip || atom2 < atomSkip) {
      continue;
    }

    // We are above the atoms we care about
    if (atom1 > atomIndex || atom2 > atomIndex) {
      continue;
    } */

    if (atom1 < molecule.atomCount() && atom2 < molecule.atomCount())
      molecule.addBond(atom1, atom2, 1); // Always a single bond
  }

  for (char l: altLocs) {
    Array<Vector3> coordinateSet = molecule.atomPositions3d();
    bool found = false;
    for (size_t i = 0; i < altAtomLocs.size(); i++) {
      if (altAtomLocs[i] == l) {
        found = true;
        coordinateSet[altAtomIds[i]] = altAtomPositions[i];
      }
    }
    if (found) {
      molecule.setCoordinate3d(
        coordinateSet,
        molecule.coordinate3dCount() ? molecule.coordinate3dCount() : 1
      );
    }
  }

  return true;
}

bool MMTFFormat::write(std::ostream& out, const Core::Molecule& molecule)
{
  return false;
}

vector<std::string> MMTFFormat::fileExtensions() const
{
  vector<std::string> ext;
  ext.emplace_back("mmtf");
  return ext;
}

vector<std::string> MMTFFormat::mimeTypes() const
{
  vector<std::string> mime;
  mime.emplace_back("chemical/x-mmtf");
  return mime;
}

} // namespace Avogadro
