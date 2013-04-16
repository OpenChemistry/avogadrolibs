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

#include "atom.h"
#include "bond.h"
#include "elements.h"
#include "graph.h"
#include "mdlvalence_p.h"
#include "molecule.h"
#include "vector.h"

#include <algorithm>
#include <cmath>
#include <vector>

// C'mon windows....
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::atomValence;
using Avogadro::Core::Molecule;

typedef std::vector<Avogadro::Core::Bond> NeighborListType;

namespace {

// Return the other atom in the bond.
inline Atom getOtherAtom(const Atom &atom, const Bond &bond)
{
  return bond.atom1().index() != atom.index() ? bond.atom1() : bond.atom2();

}

inline unsigned int countExistingBonds(const NeighborListType &bonds)
{
  unsigned int result(0);
  for (NeighborListType::const_iterator it = bonds.begin(), itEnd = bonds.end();
       it != itEnd; ++it) {
    result += static_cast<unsigned int>(it->order());
  }
  return result;
}

inline unsigned int lookupValency(const Atom &atom,
                                   unsigned int numExistingBonds)
{
  char charge(0); /// todo No charges (yet?)...
  return atomValence(atom.atomicNumber(), charge, numExistingBonds);
}

inline float hydrogenBondDistance(unsigned char otherAtomicNumber)
{
  static double hCovRadius(
        Avogadro::Core::Elements::radiusCovalent(otherAtomicNumber));
  double covRadius =
      Avogadro::Core::Elements::radiusCovalent(otherAtomicNumber);
  return static_cast<float>(hCovRadius + covRadius);
}

} // end anon namespace

namespace Avogadro {
namespace Core {

void HydrogenTools::removeAllHydrogens(Molecule &molecule)
{
  const std::vector<unsigned char> atomicNums(molecule.atomicNumbers());
  size_t atomIndex = molecule.atomCount() - 1;
  for (std::vector<unsigned char>::const_reverse_iterator
       it = atomicNums.rbegin(), itEnd = atomicNums.rend(); it != itEnd;
       ++it, --atomIndex) {
    if (*it == 1)
      molecule.removeAtom(atomIndex);
  }
}

void HydrogenTools::adjustHydrogens(Molecule &molecule, Adjustment adjustment)
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
    const Atom atom(molecule.atom(atomIndex));
    int adjustment = valencyAdjustment(atom);
    // Add hydrogens:
    if (doAdd && adjustment > 0) {
      newHPos.clear();
      generateNewHydrogenPositions(atom, adjustment, newHPos);
      for (std::vector<Vector3>::const_iterator it = newHPos.begin(),
           itEnd = newHPos.end(); it != itEnd; ++it) {
        Atom newH(molecule.addAtom(1));
        newH.setPosition3d(*it);
        molecule.addBond(atom, newH, 1);
      }
    }
    // Add bad hydrogens to our list of hydrogens to remove:
    else if (doRemove && adjustment < 0) {
      extraHydrogenIndices(atom, -adjustment, badHIndices);
    }
  }

  // Remove dead hydrogens now. Remove them in reverse-index order to keep
  // indexing sane.
  if (doRemove && !badHIndices.empty()) {
    std::sort(badHIndices.begin(), badHIndices.end());
    std::vector<size_t>::iterator newEnd(std::unique(badHIndices.begin(),
                                                     badHIndices.end()));
    badHIndices.resize(std::distance(badHIndices.begin(), newEnd));
    for (std::vector<size_t>::const_reverse_iterator it = badHIndices.rbegin(),
         itEnd = badHIndices.rend(); it != itEnd; ++it) {
      molecule.removeAtom(*it);
    }
  }
}

int HydrogenTools::valencyAdjustment(const Atom &atom)
{
  int result = 0;
  if (atom.isValid()) {
    const NeighborListType bonds(atom.molecule()->bonds(atom));
    const unsigned int numberOfBonds(countExistingBonds(bonds));
    const unsigned int valency(lookupValency(atom, numberOfBonds));
    result = static_cast<int>(valency) - static_cast<int>(numberOfBonds);
  }
  return result;
}

int HydrogenTools::extraHydrogenIndices(const Atom &atom,
                                         int numberOfHydrogens,
                                         std::vector<size_t> &indices)
{
  if (!atom.isValid())
    return 0;

  int result = 0;
  const NeighborListType bonds(atom.molecule()->bonds(atom));
  for (NeighborListType::const_iterator it = bonds.begin(), itEnd = bonds.end();
       it != itEnd && result < numberOfHydrogens; ++it) {
    const Atom otherAtom = getOtherAtom(atom, *it);
    if (otherAtom.atomicNumber() == 1) {
      indices.push_back(otherAtom.index());
      ++result;
    }
  }

  return result;
}

void HydrogenTools::generateNewHydrogenPositions(
    const Atom &atom, int numberOfHydrogens, std::vector<Vector3> &positions)
{
  if (!atom.isValid())
    return;

  // Get a list of all bond vectors (normalized, pointing away from 'atom')
  std::vector<Vector3> allVectors;
  const NeighborListType bonds(atom.molecule()->bonds(atom));
  allVectors.reserve(bonds.size() + static_cast<size_t>(numberOfHydrogens));
  for (NeighborListType::const_iterator it = bonds.begin(), itEnd = bonds.end();
       it != itEnd; ++it) {
    Atom otherAtom = getOtherAtom(atom, *it);
    Vector3 delta = otherAtom.position3d() - atom.position3d();
    if (!delta.isZero(1e-5))
      allVectors.push_back(delta.normalized());
  }

  // Tolerance for two vectors being "too close" in radians (pi/8).
  const Avogadro::Real cosRadTol =
      cos(static_cast<Avogadro::Real>(M_PI) / static_cast<Avogadro::Real>(8.));

  const Avogadro::Real bondLength = hydrogenBondDistance(atom.atomicNumber());

  // Try 10 times to generate a random vector that doesn't overlap with
  // an existing bond. If we can't, just give up and let the overlap occur.
  for (int impHIndex = 0; impHIndex < numberOfHydrogens; ++impHIndex) {
    Vector3 newPos;
    bool success = false;
    for (int attempt = 0; !success && attempt < 10; ++attempt) {
      newPos = Vector3::Random().normalized();
      success = true;
      for (std::vector<Vector3>::const_iterator it = allVectors.begin(),
           itEnd = allVectors.end(); success && it != itEnd; ++it) {
        success = newPos.dot(*it) < cosRadTol;
      }
    }

    allVectors.push_back(newPos);
    positions.push_back(atom.position3d() + (newPos * bondLength));
  }
}

} // namespace Core
} // namespace Avogadro
