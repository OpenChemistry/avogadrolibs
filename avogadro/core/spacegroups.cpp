/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <algorithm> // for std::count()
#include <cassert>
#include <cctype> // for isdigit()
#include <iostream>

#include "array.h"
#include "crystaltools.h"
#include "molecule.h"
#include "spacegroupdata.h"
#include "unitcell.h"
#include "utilities.h"
#include "vector.h"

#include "spacegroups.h"

namespace Avogadro {
namespace Core {

SpaceGroups::SpaceGroups()
{
}

SpaceGroups::~SpaceGroups()
{
}

CrystalSystem SpaceGroups::crystalSystem(unsigned short hallNumber)
{
  if (hallNumber == 1 || hallNumber == 2)
    return Triclinic;
  if (hallNumber >= 3 && hallNumber <= 107)
    return Monoclinic;
  if (hallNumber >= 108 && hallNumber <= 348)
    return Orthorhombic;
  if (hallNumber >= 349 && hallNumber <= 429)
    return Tetragonal;
  if (hallNumber >= 430 && hallNumber <= 461) {
    // 14 of these are rhombohedral and the rest are trigonal
    switch (hallNumber) {
      case 433:
      case 434:
      case 436:
      case 437:
      case 444:
      case 445:
      case 450:
      case 451:
      case 452:
      case 453:
      case 458:
      case 459:
      case 460:
      case 461:
        return Rhombohedral;
      default:
        return Trigonal;
    }
  }
  if (hallNumber >= 462 && hallNumber <= 488)
    return Hexagonal;
  if (hallNumber >= 489 && hallNumber <= 530)
    return Cubic;
  // hallNumber must be 0 or > 531
  return None;
  // for (unsigned short i = 0; i < hallNumberCount; ++i)
}

unsigned short SpaceGroups::internationalNumber(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_international_number[hallNumber];
  else
    return space_group_international_number[0];
}

const char* SpaceGroups::schoenflies(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_schoenflies[hallNumber];
  else
    return space_group_schoenflies[0];
}

const char* SpaceGroups::hallSymbol(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_hall_symbol[hallNumber];
  else
    return space_group_hall_symbol[0];
}

const char* SpaceGroups::international(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_international[hallNumber];
  else
    return space_group_international[0];
}

const char* SpaceGroups::internationalFull(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_international_full[hallNumber];
  else
    return space_group_international_full[0];
}

const char* SpaceGroups::internationalShort(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_international_short[hallNumber];
  else
    return space_group_international_short[0];
}

const char* SpaceGroups::setting(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_setting[hallNumber];
  else
    return space_group_setting[0];
}

unsigned short SpaceGroups::transformsCount(unsigned short hallNumber)
{
  if (hallNumber <= 530) {
    std::string s = transformsString(hallNumber);
    return std::count(s.begin(), s.end(), ' ') + 1;
  } else {
    return 0;
  }
}

Real readTransformCoordinate(const std::string& coordinate, const Vector3& v)
{
  // The coordinate should be at least 1 character
  assert(coordinate.size() != 0);

  Real ret = 0.0;
  Index i = 0;
  while (i < coordinate.size()) {
    bool isNeg = false;
    if (coordinate[i] == '-') {
      isNeg = true;
      ++i;
      assert(i < coordinate.size());
    }
    // We assume we are adding, so no need for a boolean here
    else if (coordinate[i] == '+') {
      ++i;
      assert(i < coordinate.size());
    }

    // Check to see if we have a digit
    if (isdigit(coordinate[i])) {
      // We SHOULD have a fraction. Also, we SHOULD only deal with single
      // digit numbers. Add assertions to make sure this is the case.
      assert(i + 2 < coordinate.size());
      assert(coordinate[i + 1] == '/');
      assert(isdigit(coordinate[i + 2]));
      // Assert that this is a single digit number
      if (coordinate.size() > i + 3)
        assert(!isdigit(coordinate[i + 3]));
      // Ancient methods used by our forefathers to cast a char to an int
      Real numerator = coordinate[i] - '0';
      Real denominator = coordinate[i + 2] - '0';
      Real fraction = numerator / denominator;
      fraction *= (isNeg) ? -1.0 : 1.0;

      ret += fraction;
      i += 3;
    } else if (coordinate[i] == 'x') {
      ret += (isNeg) ? -1.0 * v[0] : v[0];
      ++i;
    } else if (coordinate[i] == 'y') {
      ret += (isNeg) ? -1.0 * v[1] : v[1];
      ++i;
    } else if (coordinate[i] == 'z') {
      ret += (isNeg) ? -1.0 * v[2] : v[2];
      ++i;
    } else {
      std::cerr << "In " << __FUNCTION__ << ", error reading string: '"
                << coordinate << "'\n";
      return 0;
    }
  }
  return ret;
}

Vector3 getSingleTransform(const std::string& transform, const Vector3& v)
{
  Vector3 ret;
  std::vector<std::string> coordinates = split(transform, ',');

  // This should be 3 in size. Something very bad happened if it is not.
  assert(coordinates.size() == 3);

  ret[0] = readTransformCoordinate(coordinates[0], v);
  ret[1] = readTransformCoordinate(coordinates[1], v);
  ret[2] = readTransformCoordinate(coordinates[2], v);
  return ret;
}

Array<Vector3> SpaceGroups::getTransforms(unsigned short hallNumber,
                                          const Vector3& v)
{
  if (hallNumber == 0 || hallNumber > 530)
    return Array<Vector3>();

  Array<Vector3> ret;

  std::string transformsStr = transformsString(hallNumber);
  // These transforms are separated by spaces
  std::vector<std::string> transforms = split(transformsStr, ' ');

  for (Index i = 0; i < transforms.size(); ++i)
    ret.push_back(getSingleTransform(transforms[i], v));

  return ret;
}

void SpaceGroups::fillUnitCell(Molecule& mol, unsigned short hallNumber,
                               double cartTol)
{
  if (!mol.unitCell())
    return;
  UnitCell* uc = mol.unitCell();

  Array<unsigned char> atomicNumbers = mol.atomicNumbers();
  Array<Vector3> positions = mol.atomPositions3d();
  Index numAtoms = mol.atomCount();

  // We are going to loop through the original atoms. That is why
  // we have numAtoms cached instead of using atomCount().
  for (Index i = 0; i < numAtoms; ++i) {
    unsigned char atomicNum = atomicNumbers[i];
    Vector3 pos = uc->toFractional(positions[i]);

    Array<Vector3> newAtoms = getTransforms(hallNumber, pos);

    // We skip 0 because it is the original atom.
    for (Index j = 1; j < newAtoms.size(); ++j) {
      // The new atoms are in fractional coordinates. Convert to cartesian.
      Vector3 newCandidate = uc->toCartesian(newAtoms[j]);

      // If there is already an atom in this location within a
      // certain tolerance, do not add the atom.
      bool atomAlreadyPresent = false;
      for (Index k = 0; k < mol.atomCount(); k++) {
        // If it does not have the same atomic number, skip over it.
        if (mol.atomicNumber(k) != atomicNum)
          continue;
        Real distance = uc->distance(mol.atomPosition3d(k), newCandidate);
        if (distance <= cartTol)
          atomAlreadyPresent = true;
      }

      // If there is already an atom present here, just continue
      if (atomAlreadyPresent)
        continue;

      // If we got this far, add the atom!
      Atom newAtom = mol.addAtom(atomicNum);
      newAtom.setPosition3d(newCandidate);
    }
  }
  CrystalTools::wrapAtomsToUnitCell(mol);
}

void SpaceGroups::reduceToAsymmetricUnit(Molecule& mol,
                                         unsigned short hallNumber,
                                         double cartTol)
{
  if (!mol.unitCell())
    return;
  UnitCell* uc = mol.unitCell();

  // The number of atoms may change as we remove atoms, so don't cache
  // the number of atoms, atomic positions, or atomic numbers
  // There's no point in looking at the last atom
  for (Index i = 0; i + 1 < mol.atomCount(); ++i) {
    unsigned char atomicNum = mol.atomicNumber(i);
    Vector3 pos = uc->toFractional(mol.atomPosition3d(i));
    Array<Vector3> transformAtoms = getTransforms(hallNumber, pos);

    // Loop through the rest of the atoms in this crystal and see if any match
    // up with a transform
    for (Index j = i + 1; j < mol.atomCount(); ++j) {
      // If the atomic number does not match, skip over it
      if (mol.atomicNumber(j) != atomicNum)
        continue;

      Vector3 trialPos = mol.atomPosition3d(j);
      // Loop through the transform atoms
      // We skip 0 because it is the original atom.
      for (Index k = 1; k < transformAtoms.size(); ++k) {
        // The transform atoms are in fractional coordinates. Convert to
        // cartesian.
        Vector3 transformPos = uc->toCartesian(transformAtoms[k]);
        Real distance = uc->distance(trialPos, transformPos);
        // Is the atom within the cartesian tolerance distance?
        if (distance <= cartTol) {
          // Remove this atom and adjust the index
          mol.removeAtom(j);
          --j;
          break;
        }
      }
    }
  }
}

const char* SpaceGroups::transformsString(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_transforms[hallNumber];
  else
    return "";
}

} // end Core namespace
} // end Avogadro namespace
