/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "secondarystructure.h"

#include <cstdlib>
#include <limits>

#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>

namespace Avogadro {
namespace Core {

using namespace std;

SecondaryStructureAssigner::SecondaryStructureAssigner(Molecule* mol)
  : m_molecule(mol)
{}

SecondaryStructureAssigner::~SecondaryStructureAssigner() {}

//! Adapted from 3DMol.js parsers.js
//! https://github.com/3dmol/3Dmol.js/blob/master/3Dmol/parsers.js
void SecondaryStructureAssigner::assign(Molecule* mol)
{
  // Clear the current secondary structure
  auto allResidues = mol->residues();
  for (auto residue : allResidues)
    residue.setSecondaryStructure(Residue::SecondaryStructure::undefined);

  //  First assign the hydrogen bonds along the backbone
  std::vector<hBondRecord> hBonds = assignBackboneHydrogenBonds(mol);
  float infinity = std::numeric_limits<float>::max();
  // Then assign the alpha helix by going through the hBond records
  for (auto hBond : hBonds) {
    if (hBond.distSquared < infinity) {
      // check to see how far apart the residues are
      int separation = std::abs(int(hBond.residue - hBond.residuePair));
      // just alpha for now
      if (separation == 4)
        allResidues[hBond.residue].setSecondaryStructure(
          Residue::SecondaryStructure::alphaHelix);
      // TODO
      // 3-10 helix
      // pi-helix
    }
  }

  // Plug gaps in the helix
  for (auto i = 1; i < allResidues.size() - 1; ++i) {
    // check that before and after this residue are in the same chain
    if (allResidues[i].chainId() == allResidues[i - 1].chainId() ||
        allResidues[i].chainId() == allResidues[i + 1].chainId())
      continue;

    auto current = allResidues[i].secondaryStructure();
    auto previous = allResidues[i - 1].secondaryStructure();
    auto next = allResidues[i + 1].secondaryStructure();
    // is there a gap in a helix (before and after are helix, so this should be)
    if (previous != Residue::SecondaryStructure::undefined &&
        previous == next && current != previous)
      allResidues[i].setSecondaryStructure(previous);
  }

  // Then assign the beta sheet - but only if a residue isn't assigned
  const Residue::SecondaryStructure maybeBeta =
    static_cast<const Residue::SecondaryStructure>(-3);
  for (auto hBond : hBonds) {
    if (hBond.distSquared < infinity) {
      if (allResidues[hBond.residue].secondaryStructure() ==
          Residue::SecondaryStructure::undefined)
        allResidues[hBond.residue].setSecondaryStructure(maybeBeta);
    }
  }

  // Check that sheets bond to other sheets
  for (auto hBond : hBonds) {
    if (hBond.distSquared < infinity) {
      // find the match
      auto current = allResidues[hBond.residue];
      auto match = allResidues[hBond.residuePair];

      // if we're "maybe" beta see if the match is either beta or "maybe"
      if (current.secondaryStructure() == maybeBeta &&
          (match.secondaryStructure() == maybeBeta ||
           match.secondaryStructure() ==
             Residue::SecondaryStructure::betaSheet)) {
        // we can be sure now
        current.setSecondaryStructure(Residue::SecondaryStructure::betaSheet);
        match.setSecondaryStructure(Residue::SecondaryStructure::betaSheet);
      }
    }
  }

  // Plug gaps in the beta sheet
  for (auto i = 1; i < allResidues.size() - 1; ++i) {
    // check that before and after this residue are in the same chain
    if (allResidues[i].chainId() == allResidues[i - 1].chainId() ||
        allResidues[i].chainId() == allResidues[i + 1].chainId())
      continue;

    auto current = allResidues[i].secondaryStructure();
    auto previous = allResidues[i - 1].secondaryStructure();
    auto next = allResidues[i + 1].secondaryStructure();
    // is there a gap in a beta sheet?
    if (previous == Residue::SecondaryStructure::betaSheet &&
        previous == next && current != previous)
      allResidues[i].setSecondaryStructure(previous);
  }

  // remove singletons
  for (auto i = 1; i < allResidues.size() - 1; ++i) {
    // check that before and after this residue are in the same chain
    if (allResidues[i].chainId() == allResidues[i - 1].chainId() ||
        allResidues[i].chainId() == allResidues[i + 1].chainId())
      continue;

    auto current = allResidues[i].secondaryStructure();
    if (current != Residue::SecondaryStructure::undefined) {
      // make sure we don't have one lone odd assignment
      if (current != allResidues[i - 1].secondaryStructure() &&
          current != allResidues[i + 1].secondaryStructure()) {
        allResidues[i].setSecondaryStructure(
          Residue::SecondaryStructure::undefined);
      }
    }
  } // end loop over residues (for singletons)
}

//! Adapted from 3DMol.js parsers.js  assignBackboneHBond
//! https://github.com/3dmol/3Dmol.js/blob/master/3Dmol/parsers.js
std::vector<hBondRecord>
SecondaryStructureAssigner::assignBackboneHydrogenBonds(Molecule* mol)
{
  const float maxDist = 3.2;                 // in Angstroms
  const float maxDistSq = maxDist * maxDist; // 10.24

  std::vector<hBondRecord> hBonds;

  // Loop over the backbone atoms
  // we're just considering N and O (on a peptide)
  for (auto residue : mol->residues()) {
    if (residue.isHeterogen())
      continue;

    auto oxygen = residue.getAtomByName("O");
    hBondRecord oRecord;
    oRecord.atom = oxygen.index();
    oRecord.atomZ = oxygen.position3d()[2];
    oRecord.distSquared = std::numeric_limits<float>::max();
    oRecord.residue = residue.residueId();
    oRecord.residuePair = residue.residueId(); // just a placeholder
    hBonds.push_back(oRecord);

    auto nitrogen = residue.getAtomByName("N");
    hBondRecord nRecord;
    nRecord.atom = nitrogen.index();
    nRecord.atomZ = nitrogen.position3d()[2];
    nRecord.distSquared = std::numeric_limits<float>::max();
    nRecord.residue = residue.residueId();
    nRecord.residuePair = residue.residueId();
    hBonds.push_back(nRecord);
  }

  // sort by z-coordinate
  std::sort(hBonds.begin(), hBonds.end(),
            // lambda for sorting by z-coordinate [2]
            [](hBondRecord const& a, hBondRecord const& b) {
              return a.atomZ < b.atomZ;
            });

  // now loop through the sorted list (so we can exit quickly)
  int n = hBonds.size();
  for (unsigned int i = 0; i < n; ++i) {
    auto recordI = hBonds[i];
    auto residueI = mol->residue(recordI.residue);

    for (unsigned int j = i + 1; j < n; ++j) {
      auto recordJ = hBonds[j];
      auto residueJ = mol->residue(recordJ.residue);

      if (residueI.chainId() == residueJ.chainId() &&
          std::abs(int(residueI.residueId() - residueJ.residueId())) < 3)
        continue; // either the same or too close to each other

      // compute the distance between the two atoms
      float zDiff = fabs(mol->atomPosition3d(recordJ.atom)[2] -
                         mol->atomPosition3d(recordI.atom)[2]);
      if (zDiff > maxDist) // everything else is too far away
        break;

      // x and y, we just skip this atom
      float yDiff = fabs(mol->atomPosition3d(recordJ.atom)[1] -
                         mol->atomPosition3d(recordI.atom)[1]);
      if (yDiff > maxDist)
        continue;
      float xDiff = fabs(mol->atomPosition3d(recordJ.atom)[0] -
                         mol->atomPosition3d(recordI.atom)[0]);
      if (xDiff > maxDist)
        continue;

      // compute the squared distance between the two atoms
      float distSq = xDiff * xDiff + yDiff * yDiff + zDiff * zDiff;
      if (distSq > maxDistSq)
        continue;

      // if we get here, we have a potential hydrogen bond
      // select the one with the shortest distance
      if (distSq < recordI.distSquared) {
        recordI.distSquared = distSq;
        recordI.residuePair = recordJ.residue;
      }
      if (distSq < recordJ.distSquared) {
        recordJ.distSquared = distSq;
        recordJ.residuePair = recordI.residue;
      }
    } // end for(j)
  }   // end for(i)
  return hBonds;
}

} // namespace Core
} // namespace Avogadro
