/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/internalcoordinates.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <cmath>

using Avogadro::Real;
using Avogadro::Vector3;
using Avogadro::Core::Array;
using Avogadro::Core::cartesianToInternal;
using Avogadro::Core::InternalCoordinate;
using Avogadro::Core::internalToCartesian;
using Avogadro::Core::Molecule;

namespace {

// Compare interatomic distances rather than absolute positions
// since internal->Cartesian reconstruction may differ in orientation
double distance(const Vector3& a, const Vector3& b)
{
  return (a - b).norm();
}

} // namespace

TEST(InternalCoordinatesTest, emptyMolecule)
{
  Molecule mol;
  Array<InternalCoordinate> ic = cartesianToInternal(mol);
  EXPECT_EQ(ic.size(), static_cast<size_t>(0));
}

TEST(InternalCoordinatesTest, singleAtom)
{
  Molecule mol;
  mol.addAtom(6).setPosition3d(Vector3(1.0, 2.0, 3.0));

  Array<InternalCoordinate> ic = cartesianToInternal(mol);
  EXPECT_EQ(ic.size(), static_cast<size_t>(1));
  EXPECT_NEAR(ic[0].length, 0.0, 1e-6);
}

TEST(InternalCoordinatesTest, twoAtoms)
{
  Molecule mol;
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(1.5, 0.0, 0.0));
  mol.addBond(mol.atom(0), mol.atom(1), 1);

  Array<InternalCoordinate> ic = cartesianToInternal(mol);
  EXPECT_EQ(ic.size(), static_cast<size_t>(2));
  // Second atom should have length ~1.5
  EXPECT_NEAR(ic[1].length, 1.5, 1e-4);
}

TEST(InternalCoordinatesTest, chainRoundTrip)
{
  // Chain molecule (propane-like): C-C-C
  // Round-trip works for chain topologies where BFS tree gives
  // proper parent/grandparent references
  Molecule mol;
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(1.54, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(2.31, 1.26, 0.0));
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(1), mol.atom(2), 1);

  // Get original interatomic distances
  double d01_orig =
    distance(mol.atom(0).position3d(), mol.atom(1).position3d());
  double d12_orig =
    distance(mol.atom(1).position3d(), mol.atom(2).position3d());

  // Convert to internal coordinates
  Array<InternalCoordinate> ic = cartesianToInternal(mol);
  EXPECT_EQ(ic.size(), static_cast<size_t>(3));

  // Verify bond lengths in internal coords
  EXPECT_NEAR(ic[1].length, d01_orig, 1e-4);
  EXPECT_NEAR(ic[2].length, d12_orig, 1e-4);

  // Convert back to Cartesian
  Array<Vector3> newCoords = internalToCartesian(mol, ic);
  EXPECT_EQ(newCoords.size(), static_cast<size_t>(3));

  // Compare interatomic distances
  double d01_new = distance(newCoords[0], newCoords[1]);
  double d12_new = distance(newCoords[1], newCoords[2]);

  EXPECT_NEAR(d01_new, d01_orig, 1e-4);
  EXPECT_NEAR(d12_new, d12_orig, 1e-4);
}

TEST(InternalCoordinatesTest, butaneRoundTrip)
{
  // Butane chain: C-C-C-C (tests dihedral code path)
  Molecule mol;
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(1.54, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(2.31, 1.26, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(3.85, 1.26, 0.0));
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(1), mol.atom(2), 1);
  mol.addBond(mol.atom(2), mol.atom(3), 1);

  // Store original pairwise distances
  std::vector<double> origDist;
  for (int i = 0; i < 4; ++i)
    for (int j = i + 1; j < 4; ++j)
      origDist.push_back(
        distance(mol.atom(i).position3d(), mol.atom(j).position3d()));

  // Round-trip
  Array<InternalCoordinate> ic = cartesianToInternal(mol);
  EXPECT_EQ(ic.size(), static_cast<size_t>(4));

  Array<Vector3> newCoords = internalToCartesian(mol, ic);
  EXPECT_EQ(newCoords.size(), static_cast<size_t>(4));

  // Compare all pairwise distances
  int idx = 0;
  for (int i = 0; i < 4; ++i)
    for (int j = i + 1; j < 4; ++j) {
      double newDist = distance(newCoords[i], newCoords[j]);
      EXPECT_NEAR(newDist, origDist[idx], 1e-3)
        << "Distance mismatch between atoms " << i << " and " << j;
      ++idx;
    }
}

TEST(InternalCoordinatesTest, waterFromInternal)
{
  // Water (H2O) star topology: start from internal coords,
  // convert to Cartesian, then back to internal
  Molecule mol;
  mol.addAtom(8); // O
  mol.addAtom(1); // H
  mol.addAtom(1); // H
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(0), mol.atom(2), 1);

  Array<InternalCoordinate> ic(3);
  // Atom 0 (O): placed at origin
  // (defaults: a=b=c=MaxIndex, length=angle=dihedral=0)

  // Atom 1 (H): 0.96 A from O
  ic[1].a = 0;
  ic[1].length = 0.96;

  // Atom 2 (H): 0.96 A from O, H-O-H angle = 104.5 deg
  ic[2].a = 0;
  ic[2].b = 1;
  ic[2].length = 0.96;
  ic[2].angle = 104.5;

  // Convert to Cartesian
  Array<Vector3> coords = internalToCartesian(mol, ic);
  ASSERT_EQ(coords.size(), static_cast<size_t>(3));

  // Verify O-H bond lengths
  EXPECT_NEAR(distance(coords[0], coords[1]), 0.96, 1e-4);
  EXPECT_NEAR(distance(coords[0], coords[2]), 0.96, 1e-4);

  // Verify H-O-H angle via H-H distance
  // H-H = 2 * r * sin(theta/2)
  double expectedHH = 2.0 * 0.96 * std::sin(104.5 / 2.0 * M_PI / 180.0);
  EXPECT_NEAR(distance(coords[1], coords[2]), expectedHH, 1e-3);

  // Set positions on molecule and convert back to internal
  for (size_t i = 0; i < 3; ++i)
    mol.atom(i).setPosition3d(coords[i]);

  Array<InternalCoordinate> ic2 = cartesianToInternal(mol);
  ASSERT_EQ(ic2.size(), static_cast<size_t>(3));

  // Bond lengths should survive the round-trip
  EXPECT_NEAR(ic2[1].length, 0.96, 1e-4);
  EXPECT_NEAR(ic2[2].length, 0.96, 1e-4);
}

TEST(InternalCoordinatesTest, methaneFromInternal)
{
  // Methane (CH4) star topology: start from internal coords,
  // convert to Cartesian, then back to internal
  Molecule mol;
  mol.addAtom(6); // C
  mol.addAtom(1); // H
  mol.addAtom(1); // H
  mol.addAtom(1); // H
  mol.addAtom(1); // H
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(0), mol.atom(2), 1);
  mol.addBond(mol.atom(0), mol.atom(3), 1);
  mol.addBond(mol.atom(0), mol.atom(4), 1);

  Real chBond = 1.09;
  Real tetAngle = 109.4712; // tetrahedral angle in degrees

  Array<InternalCoordinate> ic(5);
  // Atom 0 (C): origin

  // Atom 1 (H): bonded to C
  ic[1].a = 0;
  ic[1].length = chBond;

  // Atom 2 (H): bonded to C, angle H-C-H = tetrahedral
  ic[2].a = 0;
  ic[2].b = 1;
  ic[2].length = chBond;
  ic[2].angle = tetAngle;

  // Atom 3 (H): bonded to C, tetrahedral angle, dihedral = 120 deg
  ic[3].a = 0;
  ic[3].b = 1;
  ic[3].c = 2;
  ic[3].length = chBond;
  ic[3].angle = tetAngle;
  ic[3].dihedral = 120.0;

  // Atom 4 (H): bonded to C, tetrahedral angle, dihedral = -120 deg
  ic[4].a = 0;
  ic[4].b = 1;
  ic[4].c = 2;
  ic[4].length = chBond;
  ic[4].angle = tetAngle;
  ic[4].dihedral = -120.0;

  // Convert to Cartesian
  Array<Vector3> coords = internalToCartesian(mol, ic);
  ASSERT_EQ(coords.size(), static_cast<size_t>(5));

  // All C-H bond lengths should be chBond
  for (int i = 1; i <= 4; ++i)
    EXPECT_NEAR(distance(coords[0], coords[i]), chBond, 1e-4)
      << "C-H" << i << " bond length";

  // All H-H distances should be equal (tetrahedral symmetry)
  // H-H = chBond * sqrt(8/3)
  Real expectedHH = chBond * std::sqrt(8.0 / 3.0);
  for (int i = 1; i <= 4; ++i)
    for (int j = i + 1; j <= 4; ++j)
      EXPECT_NEAR(distance(coords[i], coords[j]), expectedHH, 1e-3)
        << "H" << i << "-H" << j << " distance";

  // Set positions on molecule and convert back to internal
  for (size_t i = 0; i < 5; ++i)
    mol.atom(i).setPosition3d(coords[i]);

  Array<InternalCoordinate> ic2 = cartesianToInternal(mol);
  ASSERT_EQ(ic2.size(), static_cast<size_t>(5));

  // All C-H bond lengths should survive the round-trip
  for (int i = 1; i <= 4; ++i)
    EXPECT_NEAR(ic2[i].length, chBond, 1e-4)
      << "Round-trip C-H" << i << " bond length";
}

TEST(InternalCoordinatesTest, linearTriatomic)
{
  // CO2-like: O-C-O along x-axis
  Molecule mol;
  mol.addAtom(8).setPosition3d(Vector3(-1.16, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(8).setPosition3d(Vector3(1.16, 0.0, 0.0));
  mol.addBond(mol.atom(0), mol.atom(1), 2);
  mol.addBond(mol.atom(1), mol.atom(2), 2);

  Array<InternalCoordinate> ic = cartesianToInternal(mol);
  EXPECT_EQ(ic.size(), static_cast<size_t>(3));

  // Verify bond lengths
  EXPECT_NEAR(ic[1].length, 1.16, 1e-3);
  EXPECT_NEAR(ic[2].length, 1.16, 1e-3);
}
