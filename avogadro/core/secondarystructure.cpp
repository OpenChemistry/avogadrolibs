/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "secondarystructure.h"

#include <cstdlib>
#include <iostream>
#include <limits>

#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>

namespace Avogadro {
namespace Core {

using namespace std;

SecondaryStructureAssigner::SecondaryStructureAssigner(Molecule* mol)
  : m_molecule(mol)
{}

SecondaryStructureAssigner::~SecondaryStructureAssigner()
{
  for (auto hBond : m_hBonds)
    delete hBond;
  m_hBonds.clear();
}

//! Adapted from 3DMol.js parsers.js
//! https://github.com/3dmol/3Dmol.js/blob/master/3Dmol/parsers.js
void SecondaryStructureAssigner::assign(Molecule* mol)
{
  m_molecule = mol;

  // Clear the current secondary structure
  auto residueCount = m_molecule->residues().size();
  for (auto residue : m_molecule->residues())
    residue.setSecondaryStructure(Residue::SecondaryStructure::undefined);

  //  First assign the hydrogen bonds along the backbone
  assignBackboneHydrogenBonds();

  float infinity = std::numeric_limits<float>::max();
  // Then assign the alpha helix by going through the hBond records
  for (auto hBond : m_hBonds) {
    if (hBond->distSquared < infinity) {
      // check to see how far apart the residues are
      int separation = std::abs(int(hBond->residue - hBond->residuePair));

      // just alpha for now
      if (separation == 4) {
        m_molecule->residue(hBond->residue)
          .setSecondaryStructure(Residue::SecondaryStructure::alphaHelix);
      }
      // TODO
      // 3-10 helix
      // pi-helix
    }
  }

  // Plug gaps in the helix
  for (auto i = 1; i < residueCount - 1; ++i) {
    // check that before and after this residue are in the same chain
    if (m_molecule->residue(i).chainId() !=
          m_molecule->residue(i - 1).chainId() ||
        m_molecule->residue(i).chainId() !=
          m_molecule->residue(i + 1).chainId())
      continue;

    auto current = m_molecule->residue(i).secondaryStructure();
    auto previous = m_molecule->residue(i - 1).secondaryStructure();
    auto next = m_molecule->residue(i + 1).secondaryStructure();
    // is there a gap in a helix (before and after are helix, so this should be)
    if (previous != Residue::SecondaryStructure::undefined &&
        previous == next && current != previous)
      m_molecule->residue(i).setSecondaryStructure(previous);
  }

  // Then assign the beta sheet - but only if a residue isn't assigned
  const Residue::SecondaryStructure maybeBeta =
    static_cast<const Residue::SecondaryStructure>(-3);
  for (auto hBond : m_hBonds) {
    if (hBond->distSquared < infinity) {
      if (m_molecule->residue(hBond->residue).secondaryStructure() ==
          Residue::SecondaryStructure::undefined)
        m_molecule->residue(hBond->residue).setSecondaryStructure(maybeBeta);
    }
  }

  // Check that sheets bond to other sheets
  for (auto hBond : m_hBonds) {
    if (hBond->distSquared < infinity) {
      // find the match
      auto current = m_molecule->residue(hBond->residue);
      auto match = m_molecule->residue(hBond->residuePair);

      // if we're "maybe" beta see if the match is either beta or "maybe"
      if (current.secondaryStructure() == maybeBeta &&
          (match.secondaryStructure() == maybeBeta ||
           match.secondaryStructure() ==
             Residue::SecondaryStructure::betaSheet)) {
        // we can be sure now
        m_molecule->residue(hBond->residue)
          .setSecondaryStructure(Residue::SecondaryStructure::betaSheet);
        m_molecule->residue(hBond->residuePair)
          .setSecondaryStructure(Residue::SecondaryStructure::betaSheet);
      }
    }
  }

  // Plug gaps in the beta sheet
  for (auto i = 1; i < residueCount - 1; ++i) {
    // check that before and after this residue are in the same chain
    if (m_molecule->residue(i).chainId() !=
          m_molecule->residue(i - 1).chainId() ||
        m_molecule->residue(i).chainId() !=
          m_molecule->residue(i + 1).chainId())
      continue;

    auto current = m_molecule->residue(i).secondaryStructure();
    auto previous = m_molecule->residue(i - 1).secondaryStructure();
    auto next = m_molecule->residue(i + 1).secondaryStructure();
    // is there a gap in a beta sheet?
    if (previous == Residue::SecondaryStructure::betaSheet &&
        previous == next && current != previous)
      m_molecule->residue(i).setSecondaryStructure(previous);
  }

  // remove singletons
  for (auto i = 1; i < residueCount - 1; ++i) {
    // check that before and after this residue are in the same chain
    if (m_molecule->residue(i).chainId() !=
          m_molecule->residue(i - 1).chainId() ||
        m_molecule->residue(i).chainId() !=
          m_molecule->residue(i + 1).chainId())
      continue;

    auto current = m_molecule->residue(i);
    // clear maybeBeta assignments (e.g. short bits)
    if (current.secondaryStructure() == maybeBeta)
      m_molecule->residue(i).setSecondaryStructure(
        Residue::SecondaryStructure::undefined);

    if (current.secondaryStructure() !=
        Residue::SecondaryStructure::undefined) {
      // make sure we don't have one lone odd assignment
      if (current.secondaryStructure() !=
            m_molecule->residue(i - 1).secondaryStructure() &&
          current.secondaryStructure() !=
            m_molecule->residue(i + 1).secondaryStructure()) {
        m_molecule->residue(i).setSecondaryStructure(
          Residue::SecondaryStructure::undefined);
      }
    }
  } // end loop over residues (for singletons)
}

//! Adapted from 3DMol.js parsers.js  assignBackboneHBond
//! https://github.com/3dmol/3Dmol.js/blob/master/3Dmol/parsers.js
void SecondaryStructureAssigner::assignBackboneHydrogenBonds()
{
  if (m_molecule == nullptr)
    return;

  const float maxDist = 3.2;                 // in Angstroms
  const float maxDistSq = maxDist * maxDist; // 10.24

  // delete any previous records
  for (auto hBond : m_hBonds)
    delete hBond;
  m_hBonds.clear();

  // Loop over the backbone atoms
  // we're just considering N and O (on a peptide)
  unsigned int i = 0; // track the residue index
  for (auto residue : m_molecule->residues()) {
    unsigned int residueId = i++;
    if (residue.isHeterogen())
      continue;

    auto oxygen = residue.getAtomByName("O");
    if (oxygen.isValid()) {
      hBondRecord* oRecord = new hBondRecord();
      oRecord->atom = oxygen.index();
      oRecord->atomZ = oxygen.position3d()[2];
      oRecord->distSquared = std::numeric_limits<float>::max();
      oRecord->residue = residueId;
      oRecord->residuePair = residueId; // just a placeholder
      m_hBonds.push_back(oRecord);
    }

    auto nitrogen = residue.getAtomByName("N");
    if (nitrogen.isValid()) {
      hBondRecord* nRecord = new hBondRecord();
      nRecord->atom = nitrogen.index();
      nRecord->atomZ = nitrogen.position3d()[2];
      nRecord->distSquared = std::numeric_limits<float>::max();
      nRecord->residue = residueId;
      nRecord->residuePair = residueId;
      m_hBonds.push_back(nRecord);
    }
  }

  if (m_hBonds.size() == 0)
    return;

  // sort by z-coordinate
  std::sort(m_hBonds.begin(), m_hBonds.end(),
            // lambda for sorting by z-coordinate [2]
            [](const hBondRecord* a, const hBondRecord* b) {
              return a->atomZ < b->atomZ;
            });

  // now loop through the sorted list (so we can exit quickly)
  int n = m_hBonds.size();
  for (unsigned int i = 0; i < n; ++i) {
    auto recordI = m_hBonds[i];
    auto residueI = m_molecule->residue(recordI->residue);

    for (unsigned int j = i + 1; j < n; ++j) {
      auto recordJ = m_hBonds[j];
      auto residueJ = m_molecule->residue(recordJ->residue);

      // skip if we're not on the same chain
      if (residueI.chainId() != residueJ.chainId())
        continue;

      if (residueI.chainId() == residueJ.chainId() &&
          std::abs(int(residueI.residueId() - residueJ.residueId())) < 3)
        continue; // either the same or too close to each other

      // compute the distance between the two atoms
      float zDiff = fabs(m_molecule->atomPosition3d(recordJ->atom)[2] -
                         m_molecule->atomPosition3d(recordI->atom)[2]);
      if (zDiff > maxDist) // everything else is too far away
        break;

      // x and y, we just skip this atom
      float yDiff = fabs(m_molecule->atomPosition3d(recordJ->atom)[1] -
                         m_molecule->atomPosition3d(recordI->atom)[1]);
      if (yDiff > maxDist)
        continue;
      float xDiff = fabs(m_molecule->atomPosition3d(recordJ->atom)[0] -
                         m_molecule->atomPosition3d(recordI->atom)[0]);
      if (xDiff > maxDist)
        continue;

      // compute the squared distance between the two atoms
      float distSq = xDiff * xDiff + yDiff * yDiff + zDiff * zDiff;
      if (distSq > maxDistSq)
        continue;

      // if we get here, we have a potential hydrogen bond
      // select the one with the shortest distance
      if (distSq < recordI->distSquared) {
        recordI->distSquared = distSq;
        recordI->residuePair = recordJ->residue;
      }
      if (distSq < recordJ->distSquared) {
        recordJ->distSquared = distSq;
        recordJ->residuePair = recordI->residue;
      }
    } // end for(j)
  }   // end for(i)
}

} // namespace Core
} // namespace Avogadro
