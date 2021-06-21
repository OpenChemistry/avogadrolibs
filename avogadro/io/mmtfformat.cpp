/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "mmtfformat.h"
#include <avogadro/core/crystaltools.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>

#include <mmtf.hpp>

#include <iomanip>
#include <iostream>

namespace Avogadro {
namespace Io {

using std::string;
using std::vector;

using Core::Array;
using Core::Atom;
using Core::BasisSet;
using Core::Bond;
using Core::CrystalTools;
using Core::Cube;
using Core::Elements;
using Core::GaussianSet;
using Core::lexicalCast;
using Core::Molecule;
using Core::Residue;
using Core::split;
using Core::Variant;

MMTFFormat::MMTFFormat() = default;

MMTFFormat::~MMTFFormat() = default;

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

    Core::UnitCell* unitCellObject =
      new Core::UnitCell(a, b, c, alpha, beta, gamma);
    molecule.setUnitCell(unitCellObject);
  }

  Index modelChainCount =
    static_cast<Index>(structure.chainsPerModel[modelIndex]);

  for (Index j = 0; j < modelChainCount; j++) {

    Index chainGroupCount =
      static_cast<Index>(structure.groupsPerChain[chainIndex]);

    bool ok;
    std::string chainid_string = structure.chainIdList[chainIndex];
    char chainid = lexicalCast<char>(chainid_string.substr(0, 1), ok);

    // A group is like a residue or other molecule in a PDB file.
    for (size_t k = 0; k < chainGroupCount; k++) {

      Index groupType = static_cast<Index>(structure.groupTypeList[groupIndex]);

      const auto& group = structure.groupList[groupType];

      Index groupId = static_cast<Index>(structure.groupIdList[groupIndex]);
      auto resname = group.groupName;

      auto& residue = molecule.addResidue(resname, groupId, chainid);

      // Save the offset before we go changing it
      Index atomOffset = atomIndex - atomSkip;
      Index groupSize = group.atomNameList.size();

      for (Index l = 0; l < groupSize; l++) {

        auto atom = molecule.addAtom(
          Elements::atomicNumberFromSymbol(group.elementList[l]));
        // Not supported by Avogadro?
        // const auto& altLocList = structure.altLocList;

        atom.setFormalCharge(group.formalChargeList[l]);
        atom.setPosition3d(
          Vector3(static_cast<Real>(structure.xCoordList[atomIndex]),
                  static_cast<Real>(structure.yCoordList[atomIndex]),
                  static_cast<Real>(structure.zCoordList[atomIndex])));

        // Stores if the group / residue is a heteroatom
        if (mmtf::is_hetatm(group.chemCompType.c_str()))
          residue.setHeterogen(true);
        std::string atomName = group.atomNameList[l];
        residue.addResidueAtom(atomName, atom);
        atomIndex++;
      }

      // Intra-resiude bonds
      for (size_t l = 0; l < group.bondOrderList.size(); l++) {

        auto atom1 = static_cast<Index>(group.bondAtomList[l * 2]);
        auto atom2 = static_cast<Index>(group.bondAtomList[l * 2 + 1]);

        char bo = static_cast<char>(group.bondOrderList[l]);

        molecule.addBond(atomOffset + atom1, atomOffset + atom2, bo);
      }

      // This is the origianl PDB Chain name
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

    auto atom1 = static_cast<size_t>(structure.bondAtomList[i * 2]);
    auto atom2 = static_cast<size_t>(structure.bondAtomList[i * 2 + 1]);

    /* Code for multiple models
    // We are below the atoms we care about
    if (atom1 < atomSkip || atom2 < atomSkip) {
      continue;
    }

    // We are above the atoms we care about
    if (atom1 > atomIndex || atom2 > atomIndex) {
      continue;
    } */

    size_t atom_idx1 = atom1 - atomSkip; // atomSkip = 0 for us (1 model)
    size_t atom_idx2 = atom2 - atomSkip;
    molecule.addBond(atom_idx1, atom_idx2, 1); // Always a single bond
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
  ext.push_back("mmtf");
  return ext;
}

vector<std::string> MMTFFormat::mimeTypes() const
{
  vector<std::string> mime;
  mime.push_back("chemical/x-mmtf");
  return mime;
}

} // namespace Io
} // namespace Avogadro
