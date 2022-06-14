/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "hydrogentools.h"

#include "../core/mdlvalence_p.h"
#include <avogadro/core/atomutilities.h>

#include <QtCore/QDebug>

#include <algorithm>
#include <cmath>
#include <vector>

// C'mon windows....
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// Angle of tetrahedron
#define M_TETRAHED 109.47122063449069389

using Avogadro::Vector3;
using Avogadro::Core::Array;
using Avogadro::Core::atomValence;
using Avogadro::QtGui::RWAtom;
using Avogadro::QtGui::RWBond;
using Avogadro::QtGui::RWMolecule;

namespace {

typedef Avogadro::Core::Array<RWBond> NeighborListType;

// Return the other atom in the bond.
inline RWAtom getOtherAtom(const RWAtom& atom, const RWBond& bond)
{
  return bond.atom1().index() != atom.index() ? bond.atom1() : bond.atom2();
}

inline unsigned int countExistingBonds(const NeighborListType& bonds)
{
  unsigned int result(0);
  for (NeighborListType::const_iterator it = bonds.begin(), itEnd = bonds.end();
       it != itEnd; ++it) {
    result += static_cast<unsigned int>(it->order());
  }
  return result;
}

inline unsigned int lookupValency(const RWAtom& atom,
                                  unsigned int numExistingBonds)
{
  signed char charge = atom.formalCharge();
  return atomValence(atom.atomicNumber(), charge, numExistingBonds);
}

inline float hydrogenBondDistance(unsigned char otherAtomicNumber)
{
  static double hCovRadius(Avogadro::Core::Elements::radiusCovalent(1));
  double covRadius =
    Avogadro::Core::Elements::radiusCovalent(otherAtomicNumber);
  return static_cast<float>(hCovRadius + covRadius);
}

} // end anon namespace

namespace Avogadro {
namespace QtGui {

void HydrogenTools::removeAllHydrogens(RWMolecule& molecule)
{
  const Array<unsigned char> atomicNums(molecule.atomicNumbers());
  size_t atomIndex = molecule.atomCount() - 1;
  for (Array<unsigned char>::const_reverse_iterator it = atomicNums.rbegin(),
                                                    itEnd = atomicNums.rend();
       it != itEnd; ++it, --atomIndex) {
    if (*it == 1)
      molecule.removeAtom(atomIndex);
  }
}

void HydrogenTools::adjustHydrogens(RWMolecule& molecule, Adjustment adjustment)
{
  // This vector stores indices of hydrogens that need to be removed. Additions
  // are made first, followed by removals to keep indexing sane.
  std::vector<size_t> badHIndices;

  // Temporary container for calls to generateNewHydrogenPositions.
  std::vector<Vector3> newHPos;

  // Convert the adjustment option to a couple of booleans
  bool doAdd(adjustment == Add || adjustment == AddAndRemove);
  bool doRemove(adjustment == Remove || adjustment == AddAndRemove);

  // Limit to only the original atoms:
  const size_t numAtoms = molecule.atomCount();

  // Iterate through all atoms in the molecule, adding hydrogens as needed
  // and building up a list of hydrogens that should be removed.
  for (size_t atomIndex = 0; atomIndex < numAtoms; ++atomIndex) {
    const RWAtom atom(molecule.atom(atomIndex));
    int hDiff = valencyAdjustment(atom);
    // Add hydrogens:
    if (doAdd && hDiff > 0) {
      newHPos.clear();
      generateNewHydrogenPositions(atom, hDiff, newHPos);
      for (std::vector<Vector3>::const_iterator it = newHPos.begin(),
                                                itEnd = newHPos.end();
           it != itEnd; ++it) {
        RWAtom newH(molecule.addAtom(1));
        newH.setPosition3d(*it);
        molecule.addBond(atom, newH, 1);
      }
    }
    // Add bad hydrogens to our list of hydrogens to remove:
    else if (doRemove && hDiff < 0) {
      extraHydrogenIndices(atom, -hDiff, badHIndices);
    }
  }

  // Remove dead hydrogens now. Remove them in reverse-index order to keep
  // indexing sane.
  if (doRemove && !badHIndices.empty()) {
    std::sort(badHIndices.begin(), badHIndices.end());
    std::vector<size_t>::iterator newEnd(
      std::unique(badHIndices.begin(), badHIndices.end()));
    badHIndices.resize(std::distance(badHIndices.begin(), newEnd));
    for (std::vector<size_t>::const_reverse_iterator it = badHIndices.rbegin(),
                                                     itEnd = badHIndices.rend();
         it != itEnd; ++it) {
      molecule.removeAtom(*it);
    }
  }
}

void HydrogenTools::adjustHydrogens(RWAtom& atom, Adjustment adjustment)
{
  // Convert the adjustment option to a couple of booleans
  bool doAdd(adjustment == Add || adjustment == AddAndRemove);
  bool doRemove(adjustment == Remove || adjustment == AddAndRemove);

  // convenience
  RWMolecule* molecule = atom.molecule();

  if (doRemove) {
    // get the list of hydrogens connected to this
    std::vector<size_t> badHIndices;

    const NeighborListType bonds(molecule->bonds(atom));
    for (NeighborListType::const_iterator it = bonds.begin(),
                                          itEnd = bonds.end();
         it != itEnd; ++it) {
      const RWAtom otherAtom = getOtherAtom(atom, *it);
      if (otherAtom.atomicNumber() == 1) {
        badHIndices.push_back(otherAtom.index());
      }
    } // end loop through bonds

    std::sort(badHIndices.begin(), badHIndices.end());
    std::vector<size_t>::iterator newEnd(
      std::unique(badHIndices.begin(), badHIndices.end()));
    badHIndices.resize(std::distance(badHIndices.begin(), newEnd));
    for (std::vector<size_t>::const_reverse_iterator it = badHIndices.rbegin(),
                                                     itEnd = badHIndices.rend();
         it != itEnd; ++it) {
      molecule->removeAtom(*it);
    }
  } // end removing H atoms on this one

  int hDiff = valencyAdjustment(atom);
  // Add hydrogens:
  if (doAdd && hDiff > 0) {
    // Temporary container for calls to generateNewHydrogenPositions.
    std::vector<Vector3> newHPos;
    generateNewHydrogenPositions(atom, hDiff, newHPos);
    for (std::vector<Vector3>::const_iterator it = newHPos.begin(),
                                              itEnd = newHPos.end();
         it != itEnd; ++it) {
      RWAtom newH(molecule->addAtom(1));
      newH.setPosition3d(*it);
      molecule->addBond(atom, newH, 1);
    }
  }
}

int HydrogenTools::valencyAdjustment(const RWAtom& atom)
{
  int result = 0;
  if (atom.isValid()) {
    const NeighborListType bonds(atom.molecule()->bonds(atom));
    // sum of bond orders
    const unsigned int numberOfBonds(countExistingBonds(bonds));
    const unsigned int valency(lookupValency(atom, numberOfBonds));
    result = static_cast<int>(valency) - static_cast<int>(numberOfBonds);
  }

  //  qDebug() << " valence adjustment " << result;
  return result;
}

int HydrogenTools::extraHydrogenIndices(const RWAtom& atom,
                                        int numberOfHydrogens,
                                        std::vector<size_t>& indices)
{
  if (!atom.isValid())
    return 0;

  int result = 0;
  const NeighborListType bonds(atom.molecule()->bonds(atom));
  for (NeighborListType::const_iterator it = bonds.begin(), itEnd = bonds.end();
       it != itEnd && result < numberOfHydrogens; ++it) {
    const RWAtom otherAtom = getOtherAtom(atom, *it);
    if (otherAtom.atomicNumber() == 1) {
      indices.push_back(otherAtom.index());
      ++result;
    }
  }

  return result;
}

void HydrogenTools::generateNewHydrogenPositions(
  const RWAtom& atom, int numberOfHydrogens, std::vector<Vector3>& positions)
{
  if (!atom.isValid())
    return;

  // Get the hybridization
  Core::AtomHybridization hybridization = atom.hybridization();
  if (hybridization == Core::HybridizationUnknown) {
    // Perceive it
    hybridization = Core::AtomUtilities::perceiveHybridization(
        Core::Atom(dynamic_cast<Core::Molecule*>(atom.molecule()), atom.index())
    );
  }

  const Avogadro::Real bondLength = hydrogenBondDistance(atom.atomicNumber());

  // Get a list of all bond vectors (normalized, pointing away from 'atom')
  std::vector<Vector3> allVectors;
  const NeighborListType bonds(atom.molecule()->bonds(atom));
  const int explicitBonds = bonds.size();
  allVectors.reserve(bonds.size() + static_cast<size_t>(numberOfHydrogens));
  for (NeighborListType::const_iterator it = bonds.begin(), itEnd = bonds.end();
       it != itEnd; ++it) {
    RWAtom otherAtom = getOtherAtom(atom, *it);
    Vector3 delta = otherAtom.position3d() - atom.position3d();
    if (!delta.isZero(1e-5)) {
      allVectors.push_back(delta.normalized());
    }
  }

  for (int impHIndex = 0; impHIndex < numberOfHydrogens; ++impHIndex) {
    // First try to derive the bond vector based on the hybridization
    // Fallback will be to a random vector
    Vector3 newPos = Core::AtomUtilities::generateNewBondVector(
        Core::Atom(dynamic_cast<Core::Molecule*>(atom.molecule()), atom.index()),
        allVectors, hybridization
    );
    allVectors.push_back(newPos);
    positions.push_back(atom.position3d() + (newPos * bondLength));
  }
}

} // namespace QtGui
} // namespace Avogadro
