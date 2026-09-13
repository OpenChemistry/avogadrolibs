/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

using Avogadro::MaxIndex;
using Avogadro::Real;
using Avogadro::Vector3;
using Avogadro::Core::Array;
using Avogadro::Core::Constraint;

namespace {

const Real tol = 1.0e-6;

// Ethane-like fragment: two carbons along z with one hydrogen each, placed so
// that the H-C-C-H torsion is exactly 90 degrees.
Array<Vector3> stagger90()
{
  Array<Vector3> positions;
  positions.push_back(Vector3(1.0, 0.0, 0.0)); // 0: H on the first carbon
  positions.push_back(Vector3(0.0, 0.0, 0.0)); // 1: C
  positions.push_back(Vector3(0.0, 0.0, 1.5)); // 2: C
  positions.push_back(Vector3(0.0, 1.0, 1.5)); // 3: H on the second carbon
  return positions;
}

} // namespace

TEST(ConstraintTest, evaluateDistance)
{
  Array<Vector3> positions;
  positions.push_back(Vector3(0.0, 0.0, 0.0));
  positions.push_back(Vector3(3.0, 4.0, 0.0));

  Constraint c(0, 1);
  EXPECT_EQ(c.type(), Constraint::DistanceConstraint);

  Real value = 0.0;
  EXPECT_TRUE(c.evaluate(positions, value));
  EXPECT_NEAR(value, 5.0, tol);
}

TEST(ConstraintTest, evaluateAngle)
{
  Array<Vector3> positions;
  positions.push_back(Vector3(1.0, 0.0, 0.0));
  positions.push_back(Vector3(0.0, 0.0, 0.0)); // vertex
  positions.push_back(Vector3(0.0, 1.0, 0.0));

  Constraint c(0, 1, 2);
  EXPECT_EQ(c.type(), Constraint::AngleConstraint);

  // A right angle, in degrees rather than radians.
  Real value = 0.0;
  EXPECT_TRUE(c.evaluate(positions, value));
  EXPECT_NEAR(value, 90.0, tol);
}

TEST(ConstraintTest, evaluateTorsion)
{
  Constraint c(0, 1, 2, 3);
  EXPECT_EQ(c.type(), Constraint::TorsionConstraint);

  Real value = 0.0;
  EXPECT_TRUE(c.evaluate(stagger90(), value));
  EXPECT_NEAR(std::abs(value), 90.0, tol);
}

TEST(ConstraintTest, evaluateTorsionSign)
{
  // Mirroring the fourth atom mirrors the torsion, so the two differ only in
  // sign. Getting this backwards builds the wrong enantiomer.
  Array<Vector3> positions = stagger90();
  Real positive = 0.0;
  Constraint c(0, 1, 2, 3);
  ASSERT_TRUE(c.evaluate(positions, positive));

  positions[3] = Vector3(0.0, -1.0, 1.5);
  Real mirrored = 0.0;
  ASSERT_TRUE(c.evaluate(positions, mirrored));

  EXPECT_NEAR(positive, -mirrored, tol);
}

TEST(ConstraintTest, evaluateTorsionRange)
{
  // cis and trans are the ends of the range, not wrapped values.
  Array<Vector3> positions = stagger90();

  positions[3] = Vector3(1.0, 0.0, 1.5); // eclipsed
  Constraint c(0, 1, 2, 3);
  Real value = 1.0;
  ASSERT_TRUE(c.evaluate(positions, value));
  EXPECT_NEAR(value, 0.0, tol);

  positions[3] = Vector3(-1.0, 0.0, 1.5); // anti
  ASSERT_TRUE(c.evaluate(positions, value));
  EXPECT_NEAR(std::abs(value), 180.0, tol);
}

TEST(ConstraintTest, isValidRejectsMissingAtoms)
{
  // A constraint added before its atoms were deleted must not be measured
  // against positions that no longer hold them.
  Constraint distance(0, 5);
  EXPECT_FALSE(distance.isValid(4));
  EXPECT_TRUE(distance.isValid(6));

  Constraint angle(0, 1, 7);
  EXPECT_FALSE(angle.isValid(4));
  EXPECT_TRUE(angle.isValid(8));

  Constraint torsion(0, 1, 2, 9);
  EXPECT_FALSE(torsion.isValid(4));
  EXPECT_TRUE(torsion.isValid(10));
}

TEST(ConstraintTest, evaluateRejectsMissingAtoms)
{
  Array<Vector3> positions;
  positions.push_back(Vector3(0.0, 0.0, 0.0));
  positions.push_back(Vector3(1.0, 0.0, 0.0));

  // Out of range must fail rather than silently measuring to the origin.
  Constraint c(0, 4);
  Real value = -1.0;
  EXPECT_FALSE(c.evaluate(positions, value));
  EXPECT_EQ(value, -1.0);
}

TEST(ConstraintTest, evaluateRejectsOutOfPlane)
{
  // An out-of-plane constraint has no single coordinate to report here.
  Constraint c(0, 1, 2, 3);
  c.setType(Constraint::OutOfPlaneConstraint);

  Real value = -1.0;
  EXPECT_FALSE(c.evaluate(stagger90(), value));
}

TEST(ConstraintTest, scanCoordinatesRoundTripThroughProperties)
{
  Avogadro::Core::Molecule molecule;

  std::vector<Constraint> coordinates;
  coordinates.emplace_back(0, 1);       // distance
  coordinates.emplace_back(0, 1, 2);    // angle
  coordinates.emplace_back(0, 1, 2, 3); // torsion
  molecule.setScanCoordinates(coordinates);

  const std::vector<Constraint> read = molecule.scanCoordinates();
  ASSERT_EQ(read.size(), 3u);

  EXPECT_EQ(read[0].type(), Constraint::DistanceConstraint);
  EXPECT_EQ(read[0].aIndex(), 0u);
  EXPECT_EQ(read[0].bIndex(), 1u);
  // The unused atoms must come back as MaxIndex, or the type is wrong.
  EXPECT_EQ(read[0].cIndex(), MaxIndex);
  EXPECT_EQ(read[0].dIndex(), MaxIndex);

  EXPECT_EQ(read[1].type(), Constraint::AngleConstraint);
  EXPECT_EQ(read[1].cIndex(), 2u);
  EXPECT_EQ(read[1].dIndex(), MaxIndex);

  EXPECT_EQ(read[2].type(), Constraint::TorsionConstraint);
  EXPECT_EQ(read[2].dIndex(), 3u);
}

TEST(ConstraintTest, scanCoordinatesAreAbsentUntilSet)
{
  Avogadro::Core::Molecule molecule;
  EXPECT_TRUE(molecule.scanCoordinates().empty());

  // A property of the wrong type must be ignored rather than misread.
  molecule.setData("scanCoordinates", 7);
  EXPECT_TRUE(molecule.scanCoordinates().empty());
}

TEST(ConstraintTest, addScanCoordinateIgnoresDuplicates)
{
  Avogadro::Core::Molecule molecule;

  molecule.addScanCoordinate(Constraint(0, 1, 2, 3));
  molecule.addScanCoordinate(Constraint(0, 1, 2, 3));
  EXPECT_EQ(molecule.scanCoordinates().size(), 1u);

  // The same atoms in a different order describe a different coordinate.
  molecule.addScanCoordinate(Constraint(3, 2, 1, 0));
  EXPECT_EQ(molecule.scanCoordinates().size(), 2u);
}

TEST(ConstraintTest, scanCoordinatesMeasureATrajectory)
{
  // The point of storing them: measure the same coordinate in every set.
  Avogadro::Core::Molecule molecule;
  molecule.addScanCoordinate(Constraint(0, 1));

  Array<Vector3> first;
  first.push_back(Vector3(0.0, 0.0, 0.0));
  first.push_back(Vector3(1.0, 0.0, 0.0));
  Array<Vector3> second;
  second.push_back(Vector3(0.0, 0.0, 0.0));
  second.push_back(Vector3(2.5, 0.0, 0.0));

  const std::vector<Constraint> coordinates = molecule.scanCoordinates();
  ASSERT_EQ(coordinates.size(), 1u);

  Real value = 0.0;
  ASSERT_TRUE(coordinates[0].evaluate(first, value));
  EXPECT_NEAR(value, 1.0, tol);
  ASSERT_TRUE(coordinates[0].evaluate(second, value));
  EXPECT_NEAR(value, 2.5, tol);
}
