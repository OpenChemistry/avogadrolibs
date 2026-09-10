/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/angletools.h>
#include <avogadro/core/array.h>
#include <avogadro/core/internalcoordinates.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <cmath>
#include <map>

using Avogadro::calculateDihedral;
using Avogadro::Index;
using Avogadro::MaxIndex;
using Avogadro::Real;
using Avogadro::Vector3;
using Avogadro::Core::Array;
using Avogadro::Core::cartesianToInternal;
using Avogadro::Core::InternalCoordinate;
using Avogadro::Core::internalToCartesian;
using Avogadro::Core::Molecule;
using Avogadro::Core::ZMatrixOrigin;

namespace {

// Compare interatomic distances rather than absolute positions
// since internal->Cartesian reconstruction may differ in orientation
double distance(const Vector3& a, const Vector3& b)
{
  return (a - b).norm();
}

// Round-trip a molecule through its z-matrix and back. The result is
// anchored canonically rather than on the molecule's own coordinates, so the
// z-matrix alone has to carry the whole geometry -- preserving the origin
// would let a partly-empty z-matrix pass by copying positions across.
Array<Vector3> roundTrip(const Molecule& mol)
{
  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic = cartesianToInternal(mol, rowToAtom);
  return internalToCartesian(mol, ic, rowToAtom, ZMatrixOrigin::Canonical);
}

// Every pairwise distance surviving is the orientation-independent statement
// that the geometry came back unchanged.
void expectSameGeometry(const Molecule& mol, const Array<Vector3>& rebuilt,
                        double tolerance = 1e-6)
{
  ASSERT_EQ(rebuilt.size(), mol.atomCount());
  for (Index i = 0; i < mol.atomCount(); ++i) {
    for (Index j = i + 1; j < mol.atomCount(); ++j) {
      const double before =
        distance(mol.atom(i).position3d(), mol.atom(j).position3d());
      const double after = distance(rebuilt[i], rebuilt[j]);
      EXPECT_NEAR(after, before, tolerance)
        << "distance between atoms " << i << " and " << j;
    }
  }
}

// Idealised chair cyclohexane: a six-ring puckered above and below the mean
// plane. The exact geometry does not matter here, only that it is a ring.
Molecule chairCyclohexane()
{
  Molecule mol;
  for (int k = 0; k < 6; ++k) {
    const double theta = k * M_PI / 3.0;
    const double z = (k % 2 == 0) ? 0.25 : -0.25;
    mol.addAtom(6).setPosition3d(
      Vector3(1.46 * std::cos(theta), 1.46 * std::sin(theta), z));
  }
  for (int k = 0; k < 6; ++k)
    mol.addBond(mol.atom(k), mol.atom((k + 1) % 6), 1);
  return mol;
}

// Tetrahedral methane, carbon first.
Molecule methane()
{
  const double d = 1.09 / std::sqrt(3.0);
  Molecule mol;
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(1).setPosition3d(Vector3(d, d, d));
  mol.addAtom(1).setPosition3d(Vector3(d, -d, -d));
  mol.addAtom(1).setPosition3d(Vector3(-d, d, -d));
  mol.addAtom(1).setPosition3d(Vector3(-d, -d, d));
  for (int k = 1; k <= 4; ++k)
    mol.addBond(mol.atom(0), mol.atom(k), 1);
  return mol;
}

// Gauche n-butane, so that the backbone dihedral is neither 0 nor 180 and
// its sign is meaningful.
Molecule gaucheButane()
{
  Molecule mol;
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(1.54, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(2.05, 1.45, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(3.59, 1.45, 0.62));
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(1), mol.atom(2), 1);
  mol.addBond(mol.atom(2), mol.atom(3), 1);
  return mol;
}

} // namespace

TEST(InternalCoordinatesTest, emptyMolecule)
{
  Molecule mol;
  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic = cartesianToInternal(mol, rowToAtom);
  EXPECT_EQ(ic.size(), static_cast<size_t>(0));
  EXPECT_EQ(rowToAtom.size(), static_cast<size_t>(0));
}

TEST(InternalCoordinatesTest, singleAtom)
{
  Molecule mol;
  mol.addAtom(6).setPosition3d(Vector3(1.0, 2.0, 3.0));

  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic = cartesianToInternal(mol, rowToAtom);
  ASSERT_EQ(ic.size(), static_cast<size_t>(1));
  EXPECT_EQ(rowToAtom[0], Index(0));
  EXPECT_EQ(ic[0].a, MaxIndex);
  EXPECT_NEAR(ic[0].length, 0.0, 1e-6);
}

TEST(InternalCoordinatesTest, twoAtoms)
{
  Molecule mol;
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(1.5, 0.0, 0.0));
  mol.addBond(mol.atom(0), mol.atom(1), 1);

  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic = cartesianToInternal(mol, rowToAtom);
  ASSERT_EQ(ic.size(), static_cast<size_t>(2));
  EXPECT_EQ(ic[1].a, Index(0));
  EXPECT_EQ(ic[1].b, MaxIndex);
  EXPECT_NEAR(ic[1].length, 1.5, 1e-4);
}

// A branch point must not lose its bond angle. Before references were drawn
// from already-placed atoms, both hydrogens hung off the tree root with no
// grandparent, and water came back with an H-O-H angle of exactly zero.
TEST(InternalCoordinatesTest, branchedAtomKeepsBondAngle)
{
  Molecule mol;
  mol.addAtom(8).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(1).setPosition3d(Vector3(0.9572, 0.0, 0.0));
  mol.addAtom(1).setPosition3d(Vector3(-0.2400, 0.9266, 0.0));
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(0), mol.atom(2), 1);

  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic = cartesianToInternal(mol, rowToAtom);
  ASSERT_EQ(ic.size(), static_cast<size_t>(3));

  // The second hydrogen is measured against the oxygen and the first
  // hydrogen, which is the only way its angle can be expressed.
  EXPECT_EQ(ic[2].a, Index(0));
  EXPECT_EQ(ic[2].b, Index(1));
  EXPECT_NEAR(ic[2].angle, 104.52, 0.05);

  expectSameGeometry(mol, roundTrip(mol));
}

// Hydrogens on a common centre used to receive identical references, so the
// z-matrix could not tell them apart and they superimposed on rebuild.
TEST(InternalCoordinatesTest, siblingsAreDistinguishable)
{
  Molecule mol = methane();

  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic = cartesianToInternal(mol, rowToAtom);
  ASSERT_EQ(ic.size(), static_cast<size_t>(5));

  // Both need a dihedral at all: without one there is nothing to separate a
  // hydrogen from its siblings around the C-H axis.
  EXPECT_NE(ic[3].c, MaxIndex);
  EXPECT_NE(ic[4].c, MaxIndex);

  // The two rows must not be the same row. They may share a dihedral value
  // while measuring it against different atoms, which is why the references
  // are part of the comparison.
  const bool identical = ic[3].a == ic[4].a && ic[3].b == ic[4].b &&
                         ic[3].c == ic[4].c &&
                         std::abs(ic[3].dihedral - ic[4].dihedral) < 1e-6;
  EXPECT_FALSE(identical) << "rows 3 and 4 describe the same position";

  // Which shows up as the hydrogens landing on top of each other.
  const Array<Vector3> rebuilt = roundTrip(mol);
  ASSERT_EQ(rebuilt.size(), static_cast<size_t>(5));
  for (Index i = 1; i <= 4; ++i)
    for (Index j = i + 1; j <= 4; ++j)
      EXPECT_GT(distance(rebuilt[i], rebuilt[j]), 1.0)
        << "hydrogens " << i << " and " << j << " superimposed";

  expectSameGeometry(mol, rebuilt);
}

// Every reference must name an atom from an earlier row, or the rebuild
// reads a position that has not been computed yet. A molecule whose central
// atom is not first exercises this.
TEST(InternalCoordinatesTest, referencesPrecedeTheirRow)
{
  Molecule mol;
  mol.addAtom(1).setPosition3d(Vector3(1.0, 0.0, 0.0));
  mol.addAtom(1).setPosition3d(Vector3(-0.5, 0.9, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(1).setPosition3d(Vector3(-0.5, -0.45, 0.78));
  mol.addBond(mol.atom(2), mol.atom(0), 1);
  mol.addBond(mol.atom(2), mol.atom(1), 1);
  mol.addBond(mol.atom(2), mol.atom(3), 1);

  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic = cartesianToInternal(mol, rowToAtom);
  ASSERT_EQ(ic.size(), static_cast<size_t>(4));

  std::map<Index, size_t> rowOfAtom;
  for (size_t row = 0; row < rowToAtom.size(); ++row)
    rowOfAtom[rowToAtom[row]] = row;
  EXPECT_EQ(rowOfAtom.size(), static_cast<size_t>(4)) << "atoms placed twice";

  for (size_t row = 0; row < ic.size(); ++row) {
    for (Index reference : { ic[row].a, ic[row].b, ic[row].c }) {
      if (reference == MaxIndex)
        continue;
      ASSERT_EQ(rowOfAtom.count(reference), static_cast<size_t>(1))
        << "row " << row << " references atom " << reference
        << ", which is not in the matrix";
      EXPECT_LT(rowOfAtom[reference], row)
        << "row " << row << " references atom " << reference
        << " from a later row";
    }
  }

  expectSameGeometry(mol, roundTrip(mol));
}

// A molecule already in a valid z-matrix order keeps that order, so the
// editor has no reason to renumber it.
TEST(InternalCoordinatesTest, validOrderIsLeftAlone)
{
  Molecule mol = methane();

  Array<Index> rowToAtom;
  cartesianToInternal(mol, rowToAtom);
  ASSERT_EQ(rowToAtom.size(), static_cast<size_t>(5));
  for (size_t row = 0; row < rowToAtom.size(); ++row)
    EXPECT_EQ(rowToAtom[row], Index(row)) << "row " << row;
}

// Separate fragments used to be rooted at the origin one on top of another.
TEST(InternalCoordinatesTest, disconnectedFragmentsStayApart)
{
  Molecule mol;
  for (int fragment = 0; fragment < 2; ++fragment) {
    const double shift = 5.0 * fragment;
    const Index o = mol.atomCount();
    mol.addAtom(8).setPosition3d(Vector3(shift, 0.0, 0.0));
    mol.addAtom(1).setPosition3d(Vector3(shift + 0.9572, 0.0, 0.0));
    mol.addAtom(1).setPosition3d(Vector3(shift - 0.2400, 0.9266, 0.0));
    mol.addBond(mol.atom(o), mol.atom(o + 1), 1);
    mol.addBond(mol.atom(o), mol.atom(o + 2), 1);
  }

  const Array<Vector3> rebuilt = roundTrip(mol);
  ASSERT_EQ(rebuilt.size(), static_cast<size_t>(6));
  EXPECT_NEAR(distance(rebuilt[0], rebuilt[3]), 5.0, 1e-6)
    << "the two fragments collapsed onto each other";
  expectSameGeometry(mol, rebuilt);
}

TEST(InternalCoordinatesTest, chainRoundTrip)
{
  Molecule mol;
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(1.54, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(2.31, 1.26, 0.0));
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(1), mol.atom(2), 1);

  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic = cartesianToInternal(mol, rowToAtom);
  ASSERT_EQ(ic.size(), static_cast<size_t>(3));
  EXPECT_NEAR(ic[1].length, 1.54, 1e-4);
  EXPECT_NEAR(ic[2].length,
              distance(mol.atom(1).position3d(), mol.atom(2).position3d()),
              1e-4);

  expectSameGeometry(mol, roundTrip(mol));
}

TEST(InternalCoordinatesTest, butaneRoundTrip)
{
  Molecule mol = gaucheButane();
  expectSameGeometry(mol, roundTrip(mol));
}

// The dihedral has to come back with its sign intact, or a rebuild mirrors
// the molecule. This also pins cartesianToInternal() to the same convention
// as Core::calculateDihedral(), which the property tables use.
TEST(InternalCoordinatesTest, dihedralSignSurvivesRoundTrip)
{
  Molecule mol = gaucheButane();

  const Real expected =
    calculateDihedral(mol.atom(3).position3d(), mol.atom(2).position3d(),
                      mol.atom(1).position3d(), mol.atom(0).position3d());
  ASSERT_GT(std::abs(expected), 5.0) << "test needs a non-planar backbone";

  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic = cartesianToInternal(mol, rowToAtom);
  ASSERT_EQ(ic.size(), static_cast<size_t>(4));

  // Row 3 places atom 3 against 2, 1 and 0, which is that same dihedral.
  EXPECT_EQ(ic[3].a, Index(2));
  EXPECT_EQ(ic[3].b, Index(1));
  EXPECT_EQ(ic[3].c, Index(0));
  EXPECT_NEAR(ic[3].dihedral, expected, 1e-4);

  const Array<Vector3> rebuilt = roundTrip(mol);
  const Real after =
    calculateDihedral(rebuilt[3], rebuilt[2], rebuilt[1], rebuilt[0]);
  EXPECT_NEAR(after, expected, 1e-4) << "the rebuilt molecule is mirrored";
}

// The dihedral sign is not a matter of taste: reading it the wrong way round
// leaves every distance and angle correct and builds the enantiomer. This is
// the shape InsertPeptide relies on, whose residue z-matrices come from
// fragments/amino/*.zmat -- the first eight rows of ALA.zmat are reproduced
// here, with the file's 1-based references converted to 0-based.
TEST(InternalCoordinatesTest, chiralityFromZMatrix)
{
  Molecule mol;
  for (int i = 0; i < 8; ++i)
    mol.addAtom(6); // N, CA, C, O, CB, OXT, H, HA

  Array<InternalCoordinate> ic(8);
  auto row = [&ic](int i, Index a, Real length, Index b, Real angle, Index c,
                   Real dihedral) {
    ic[i].a = a;
    ic[i].length = length;
    ic[i].b = b;
    ic[i].angle = angle;
    ic[i].c = c;
    ic[i].dihedral = dihedral;
  };
  row(0, MaxIndex, 0.0, MaxIndex, 0.0, MaxIndex, 0.0);
  row(1, 0, 1.4677, MaxIndex, 0.0, MaxIndex, 0.0);
  row(2, 1, 1.5054, 0, 109.5241, MaxIndex, 0.0);
  row(3, 2, 1.2070, 1, 120.0308, 0, 330.1001);
  row(4, 1, 1.5294, 0, 109.4645, 2, 240.0009);
  row(5, 2, 1.3419, 1, 120.0083, 0, 149.9558);
  row(6, 0, 1.0084, 1, 106.7514, 2, 59.95234);
  row(7, 1, 1.0899, 0, 109.4654, 2, 120.0828);

  const Array<Vector3> pos = internalToCartesian(mol, ic);
  ASSERT_EQ(pos.size(), static_cast<size_t>(8));

  // CIP priorities at the alpha carbon are N > C(=O) > CB > HA. With the
  // three highest taken in order, a positive determinant is S and a negative
  // one is R. Alanine as tabulated is L, which is (S).
  const Vector3 toN = pos[0] - pos[1];
  const Vector3 toC = pos[2] - pos[1];
  const Vector3 toCB = pos[4] - pos[1];
  EXPECT_GT(toN.dot(toC.cross(toCB)), 0.0)
    << "the residue was built as its D enantiomer";

  // The alpha carbon should still be tetrahedral, so that a failure above is
  // read as a mirrored centre rather than a mangled one.
  const Vector3 toHA = pos[7] - pos[1];
  EXPECT_LT(toHA.dot(toN.normalized() + toC.normalized() + toCB.normalized()),
            0.0);
}

TEST(InternalCoordinatesTest, ringRoundTrip)
{
  Molecule mol = chairCyclohexane();
  expectSameGeometry(mol, roundTrip(mol));
}

// Rebuilding a molecule that has not been edited must not move it, which is
// what lets the editor rebuild without the view jumping.
TEST(InternalCoordinatesTest, preserveOriginKeepsPlacement)
{
  Molecule mol = gaucheButane();

  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic = cartesianToInternal(mol, rowToAtom);
  const Array<Vector3> rebuilt =
    internalToCartesian(mol, ic, rowToAtom, ZMatrixOrigin::Preserve);

  ASSERT_EQ(rebuilt.size(), mol.atomCount());
  for (Index i = 0; i < mol.atomCount(); ++i) {
    const Vector3 before = mol.atom(i).position3d();
    EXPECT_NEAR(rebuilt[i].x(), before.x(), 1e-6) << "atom " << i;
    EXPECT_NEAR(rebuilt[i].y(), before.y(), 1e-6) << "atom " << i;
    EXPECT_NEAR(rebuilt[i].z(), before.z(), 1e-6) << "atom " << i;
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

  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic2 = cartesianToInternal(mol, rowToAtom);
  ASSERT_EQ(ic2.size(), static_cast<size_t>(3));

  // Bond lengths and the angle should survive the round-trip
  EXPECT_NEAR(ic2[1].length, 0.96, 1e-4);
  EXPECT_NEAR(ic2[2].length, 0.96, 1e-4);
  EXPECT_NEAR(ic2[2].angle, 104.5, 1e-3);
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

  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic2 = cartesianToInternal(mol, rowToAtom);
  ASSERT_EQ(ic2.size(), static_cast<size_t>(5));

  // All C-H bond lengths should survive the round-trip
  for (int i = 1; i <= 4; ++i)
    EXPECT_NEAR(ic2[i].length, chBond, 1e-4)
      << "Round-trip C-H" << i << " bond length";
}

// A collinear molecule has no plane for a dihedral to be measured in. The
// angle is then 0 or 180, so the dihedral cannot affect where the atom sits
// and the geometry still rebuilds exactly.
TEST(InternalCoordinatesTest, linearTriatomic)
{
  Molecule mol;
  mol.addAtom(8).setPosition3d(Vector3(-1.16, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(8).setPosition3d(Vector3(1.16, 0.0, 0.0));
  mol.addBond(mol.atom(0), mol.atom(1), 2);
  mol.addBond(mol.atom(1), mol.atom(2), 2);

  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic = cartesianToInternal(mol, rowToAtom);
  ASSERT_EQ(ic.size(), static_cast<size_t>(3));
  EXPECT_NEAR(ic[1].length, 1.16, 1e-3);
  EXPECT_NEAR(ic[2].length, 1.16, 1e-3);
  EXPECT_NEAR(ic[2].angle, 180.0, 1e-3);

  expectSameGeometry(mol, roundTrip(mol));
}

TEST(InternalCoordinatesTest, linearFourAtoms)
{
  // Diacetylene-like: four collinear atoms, so no candidate for 'c' is ever
  // out of line and the fourth row falls back to a distance and an angle.
  Molecule mol;
  for (int k = 0; k < 4; ++k)
    mol.addAtom(6).setPosition3d(Vector3(1.2 * k, 0.0, 0.0));
  for (int k = 0; k < 3; ++k)
    mol.addBond(mol.atom(k), mol.atom(k + 1), 1);

  expectSameGeometry(mol, roundTrip(mol));
}

// Malformed input must not read past the end of an array.
TEST(InternalCoordinatesTest, mismatchedRowCount)
{
  Molecule mol = gaucheButane();

  Array<InternalCoordinate> ic(2);
  Array<Index> rowToAtom(3);
  rowToAtom[0] = 0;
  rowToAtom[1] = 1;
  rowToAtom[2] = 2;

  const Array<Vector3> coords =
    internalToCartesian(mol, ic, rowToAtom, ZMatrixOrigin::Canonical);
  EXPECT_EQ(coords.size(), mol.atomCount());
}

TEST(InternalCoordinatesTest, outOfRangeReferences)
{
  Molecule mol = gaucheButane();

  Array<Index> rowToAtom(4);
  Array<InternalCoordinate> ic(4);
  for (size_t row = 0; row < 4; ++row)
    rowToAtom[row] = row;

  // References naming atoms that do not exist, or that this row's own
  // position would be needed to place.
  ic[1].a = 999;
  ic[1].length = 1.5;
  ic[2].a = 0;
  ic[2].b = 3; // not placed yet
  ic[2].length = 1.5;
  ic[2].angle = 110.0;
  ic[3].a = 0;
  ic[3].b = 1;
  ic[3].c = MaxIndex;
  ic[3].length = 1.5;
  ic[3].angle = 110.0;

  const Array<Vector3> coords =
    internalToCartesian(mol, ic, rowToAtom, ZMatrixOrigin::Canonical);
  ASSERT_EQ(coords.size(), static_cast<size_t>(4));
  for (Index i = 0; i < 4; ++i) {
    EXPECT_TRUE(std::isfinite(coords[i].x())) << "atom " << i;
    EXPECT_TRUE(std::isfinite(coords[i].y())) << "atom " << i;
    EXPECT_TRUE(std::isfinite(coords[i].z())) << "atom " << i;
  }
  // The rows that were usable still honour their distance.
  EXPECT_NEAR(distance(coords[0], coords[2]), 1.5, 1e-6);
  EXPECT_NEAR(distance(coords[0], coords[3]), 1.5, 1e-6);
}

// Atoms sitting on top of each other must not produce NaN positions.
TEST(InternalCoordinatesTest, coincidentAtoms)
{
  Molecule mol;
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6).setPosition3d(Vector3(1.5, 0.0, 0.0));
  mol.addBond(mol.atom(0), mol.atom(1), 1);
  mol.addBond(mol.atom(1), mol.atom(2), 1);

  Array<Index> rowToAtom;
  Array<InternalCoordinate> ic = cartesianToInternal(mol, rowToAtom);
  ASSERT_EQ(ic.size(), static_cast<size_t>(3));
  for (size_t row = 0; row < ic.size(); ++row) {
    EXPECT_TRUE(std::isfinite(ic[row].length)) << "row " << row;
    EXPECT_TRUE(std::isfinite(ic[row].angle)) << "row " << row;
    EXPECT_TRUE(std::isfinite(ic[row].dihedral)) << "row " << row;
  }

  const Array<Vector3> rebuilt =
    internalToCartesian(mol, ic, rowToAtom, ZMatrixOrigin::Canonical);
  ASSERT_EQ(rebuilt.size(), static_cast<size_t>(3));
  for (Index i = 0; i < 3; ++i) {
    EXPECT_TRUE(std::isfinite(rebuilt[i].x())) << "atom " << i;
    EXPECT_TRUE(std::isfinite(rebuilt[i].y())) << "atom " << i;
    EXPECT_TRUE(std::isfinite(rebuilt[i].z())) << "atom " << i;
  }
}
