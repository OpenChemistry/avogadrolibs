/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/angletools.h>
#include <avogadro/qtgui/fragmenttools.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <cmath>
#include <limits>

using Avogadro::calculateAngle;
using Avogadro::calculateDihedral;
using Avogadro::Index;
using Avogadro::Real;
using Avogadro::Vector3;
using Avogadro::Core::Array;
using Avogadro::QtGui::FragmentTools;
using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::RWMolecule;

namespace {

// Staggered ethane, roughly: C0-C1 with three hydrogens on each.
// Atoms 0,1 are the carbons; 2,3,4 hang off C0 and 5,6,7 off C1.
void buildEthane(RWMolecule& mol)
{
  const Real cc = 1.54;
  const Real ch = 1.09;
  const Real theta = 109.5 * M_PI / 180.0;
  const Real r = ch * std::sin(theta - M_PI / 2.0);
  const Real z = ch * std::cos(M_PI - theta);

  mol.addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6, Vector3(0.0, 0.0, cc));
  for (int i = 0; i < 3; ++i) {
    const Real phi = i * 2.0 * M_PI / 3.0;
    mol.addAtom(1, Vector3(r * std::cos(phi), r * std::sin(phi), -z));
  }
  for (int i = 0; i < 3; ++i) {
    const Real phi = (i + 0.5) * 2.0 * M_PI / 3.0;
    mol.addAtom(1, Vector3(r * std::cos(phi), r * std::sin(phi), cc + z));
  }
  mol.addBond(0, 1, 1);
  for (Index i = 2; i < 5; ++i)
    mol.addBond(0, i, 1);
  for (Index i = 5; i < 8; ++i)
    mol.addBond(1, i, 1);
}

double distance(const Vector3& a, const Vector3& b)
{
  return (a - b).norm();
}

} // namespace

TEST(FragmentToolsTest, setDistanceCarriesTheFragment)
{
  Molecule m;
  RWMolecule mol(m);
  buildEthane(mol);

  // Record the moving side's own geometry, which must ride along rigidly.
  const double h5h6 = distance(mol.atomPosition3d(5), mol.atomPosition3d(6));
  const double c1h5 = distance(mol.atomPosition3d(1), mol.atomPosition3d(5));
  const Vector3 c0 = mol.atomPosition3d(0);
  const Vector3 h2 = mol.atomPosition3d(2);

  // Atom 1 moves, atom 0 anchors.
  ASSERT_TRUE(FragmentTools::setDistance(mol, 1, 0, 2.0));

  EXPECT_NEAR(2.0, distance(mol.atomPosition3d(0), mol.atomPosition3d(1)),
              1e-9);
  // The anchor and its own hydrogens stayed exactly put.
  EXPECT_NEAR(0.0, distance(c0, mol.atomPosition3d(0)), 1e-12);
  EXPECT_NEAR(0.0, distance(h2, mol.atomPosition3d(2)), 1e-12);
  // The moving side is rigid, not stretched.
  EXPECT_NEAR(h5h6, distance(mol.atomPosition3d(5), mol.atomPosition3d(6)),
              1e-9);
  EXPECT_NEAR(c1h5, distance(mol.atomPosition3d(1), mol.atomPosition3d(5)),
              1e-9);
}

// The sign of the rotation is the whole question here: an angle edit that
// turns the wrong way still leaves a valid geometry, just not the one asked
// for, so the test compares the resulting angle against the request.
TEST(FragmentToolsTest, setAngleReachesTheRequestedValue)
{
  Molecule m;
  RWMolecule mol(m);
  buildEthane(mol);

  for (const Real target : { 100.0, 118.0, 95.0 }) {
    ASSERT_TRUE(FragmentTools::setAngle(mol, 5, 1, 0, target))
      << "target " << target;
    const Real actual = calculateAngle(
      mol.atomPosition3d(5), mol.atomPosition3d(1), mol.atomPosition3d(0));
    EXPECT_NEAR(target, actual, 1e-6) << "target " << target;
  }

  // The vertex and the anchor did not move, only the atom named first.
  EXPECT_NEAR(1.54, distance(mol.atomPosition3d(0), mol.atomPosition3d(1)),
              1e-9);
}

// Same question for the torsion, and the same reason: a mirrored rotation is
// silently plausible.
TEST(FragmentToolsTest, setTorsionReachesTheRequestedValue)
{
  Molecule m;
  RWMolecule mol(m);
  buildEthane(mol);

  for (const Real target : { 60.0, -60.0, 175.0, 20.0 }) {
    ASSERT_TRUE(FragmentTools::setTorsion(mol, 5, 1, 0, 2, target))
      << "target " << target;
    const Real actual =
      calculateDihedral(mol.atomPosition3d(5), mol.atomPosition3d(1),
                        mol.atomPosition3d(0), mol.atomPosition3d(2));
    EXPECT_NEAR(target, actual, 1e-6) << "target " << target;
  }
}

// An edit is one undo step, not one per atom moved.
TEST(FragmentToolsTest, editsAreASingleUndoStep)
{
  Molecule m;
  RWMolecule mol(m);
  buildEthane(mol);
  const int before = mol.undoStack().count();

  Array<Vector3> original = mol.atomPositions3d();
  ASSERT_TRUE(FragmentTools::setDistance(mol, 1, 0, 2.0));
  EXPECT_EQ(before + 1, mol.undoStack().count());

  mol.undoStack().undo();
  for (Index i = 0; i < mol.atomCount(); ++i)
    EXPECT_NEAR(0.0, distance(original[i], mol.atomPosition3d(i)), 1e-9)
      << "atom " << i;
}

// A bond in a ring has no side that can move on its own, so only the named
// atom moves and the ring is not torn open.
TEST(FragmentToolsTest, ringBondMovesOnlyTheNamedAtom)
{
  Molecule m;
  RWMolecule mol(m);
  for (int k = 0; k < 6; ++k) {
    const double angle = k * M_PI / 3.0;
    mol.addAtom(6, Vector3(1.4 * std::cos(angle), 1.4 * std::sin(angle), 0.0));
  }
  for (int k = 0; k < 6; ++k)
    mol.addBond(k, (k + 1) % 6, 1);

  const Vector3 other = mol.atomPosition3d(2);
  ASSERT_TRUE(FragmentTools::setDistance(mol, 1, 0, 2.0));

  EXPECT_NEAR(2.0, distance(mol.atomPosition3d(0), mol.atomPosition3d(1)),
              1e-9);
  // Atom 2 is on atom 1's side of the ring but must not have been dragged.
  EXPECT_NEAR(0.0, distance(other, mol.atomPosition3d(2)), 1e-12);
}

// A ring bond cannot split the molecule in two, but the substituents on the
// moving atom are held by nothing except that atom, so they have to come
// along -- otherwise stretching a ring bond leaves its hydrogens behind.
TEST(FragmentToolsTest, ringBondCarriesTheMovingAtomsSubstituents)
{
  Molecule m;
  RWMolecule mol(m);

  // Cyclopentane: five ring carbons, each carrying two hydrogens.
  for (int k = 0; k < 5; ++k) {
    const double angle = k * 2.0 * M_PI / 5.0;
    mol.addAtom(6, Vector3(1.5 * std::cos(angle), 1.5 * std::sin(angle), 0.0));
  }
  for (int k = 0; k < 5; ++k)
    mol.addBond(k, (k + 1) % 5, 1);
  for (int k = 0; k < 5; ++k) {
    const double angle = k * 2.0 * M_PI / 5.0;
    for (int h = 0; h < 2; ++h) {
      const Index hydrogen = mol.atomCount();
      mol.addAtom(1, Vector3(2.1 * std::cos(angle), 2.1 * std::sin(angle),
                             h == 0 ? 0.9 : -0.9));
      mol.addBond(k, hydrogen, 1);
    }
  }

  // Hydrogens 5 and 6 sit on carbon 0, which is the atom that moves.
  const double c0h5 = distance(mol.atomPosition3d(0), mol.atomPosition3d(5));
  const double c0h6 = distance(mol.atomPosition3d(0), mol.atomPosition3d(6));
  const Vector3 c2 = mol.atomPosition3d(2);
  const Vector3 h7 = mol.atomPosition3d(7); // on carbon 1, must stay

  ASSERT_TRUE(FragmentTools::setDistance(mol, 0, 1, 2.2));
  EXPECT_NEAR(2.2, distance(mol.atomPosition3d(0), mol.atomPosition3d(1)),
              1e-9);

  // Carbon 0 took its own hydrogens with it, rigidly.
  EXPECT_NEAR(c0h5, distance(mol.atomPosition3d(0), mol.atomPosition3d(5)),
              1e-9);
  EXPECT_NEAR(c0h6, distance(mol.atomPosition3d(0), mol.atomPosition3d(6)),
              1e-9);

  // The rest of the ring, and hydrogens belonging to it, did not move.
  EXPECT_NEAR(0.0, distance(c2, mol.atomPosition3d(2)), 1e-12);
  EXPECT_NEAR(0.0, distance(h7, mol.atomPosition3d(7)), 1e-12);
}

// An internal coordinate may name atoms that are not bonded, and then there
// is no fragment to carry along.
TEST(FragmentToolsTest, unbondedReferenceMovesOneAtom)
{
  Molecule m;
  RWMolecule mol(m);
  buildEthane(mol);

  // Hydrogens 2 and 5 sit on opposite carbons and are not bonded.
  const Vector3 h3 = mol.atomPosition3d(3);
  const Vector3 c0 = mol.atomPosition3d(0);
  ASSERT_TRUE(FragmentTools::setDistance(mol, 2, 5, 3.0));

  EXPECT_NEAR(3.0, distance(mol.atomPosition3d(5), mol.atomPosition3d(2)),
              1e-9);
  // Nothing else moved, not even the carbon atom 2 is bonded to.
  EXPECT_NEAR(0.0, distance(c0, mol.atomPosition3d(0)), 1e-12);
  EXPECT_NEAR(0.0, distance(h3, mol.atomPosition3d(3)), 1e-12);
}

TEST(FragmentToolsTest, degenerateInputIsRefused)
{
  Molecule m;
  RWMolecule mol(m);
  buildEthane(mol);
  const Array<Vector3> original = mol.atomPositions3d();

  // An atom that does not exist.
  EXPECT_FALSE(FragmentTools::setDistance(mol, 0, 99, 2.0));
  // The same atom named twice.
  EXPECT_FALSE(FragmentTools::setDistance(mol, 0, 0, 2.0));
  EXPECT_FALSE(FragmentTools::setAngle(mol, 5, 1, 5, 100.0));
  EXPECT_FALSE(FragmentTools::setTorsion(mol, 5, 1, 0, 1, 60.0));

  // Nothing was moved by any of the refusals.
  for (Index i = 0; i < mol.atomCount(); ++i)
    EXPECT_NEAR(0.0, distance(original[i], mol.atomPosition3d(i)), 1e-12)
      << "atom " << i;
}

// A value that is not a number must never reach a transform: it would spread
// from there into every atom the fragment carries.
TEST(FragmentToolsTest, nonFiniteValuesAreRefused)
{
  Molecule m;
  RWMolecule mol(m);
  buildEthane(mol);
  const Array<Vector3> original = mol.atomPositions3d();

  const Real notANumber = std::numeric_limits<Real>::quiet_NaN();
  const Real infinite = std::numeric_limits<Real>::infinity();

  EXPECT_FALSE(FragmentTools::setDistance(mol, 1, 0, notANumber));
  EXPECT_FALSE(FragmentTools::setDistance(mol, 1, 0, infinite));
  EXPECT_FALSE(FragmentTools::setAngle(mol, 5, 1, 0, notANumber));
  EXPECT_FALSE(FragmentTools::setTorsion(mol, 5, 1, 0, 2, notANumber));

  // A distance is never negative either.
  EXPECT_FALSE(FragmentTools::setDistance(mol, 1, 0, -1.5));

  for (Index i = 0; i < mol.atomCount(); ++i)
    EXPECT_NEAR(0.0, distance(original[i], mol.atomPosition3d(i)), 1e-12)
      << "atom " << i;
}

// An atom held in place by a ring cannot be moved to satisfy a coordinate.
// Reporting success while moving nothing would leave the caller, and the
// table it is driving, believing the edit took.
TEST(FragmentToolsTest, edgeHeldByARingIsRefusedRatherThanIgnored)
{
  Molecule m;
  RWMolecule mol(m);
  for (int k = 0; k < 6; ++k) {
    const double angle = k * M_PI / 3.0;
    mol.addAtom(6, Vector3(1.4 * std::cos(angle), 1.4 * std::sin(angle), 0.0));
  }
  for (int k = 0; k < 6; ++k)
    mol.addBond(k, (k + 1) % 6, 1);
  const Array<Vector3> original = mol.atomPositions3d();

  // The fragment for a ring bond holds only the atom it starts from, so an
  // edit naming any other ring atom cannot be carried out.
  const Array<Index> fragment = FragmentTools::fragmentUniqueIds(
    mol, mol.bond(mol.atom(0), mol.atom(1)), mol.atom(1));
  EXPECT_FALSE(FragmentTools::setAngle(mol, 2, 1, 0, 100.0, fragment));
  EXPECT_FALSE(FragmentTools::setTorsion(mol, 3, 2, 1, 0, 40.0, fragment));

  for (Index i = 0; i < mol.atomCount(); ++i)
    EXPECT_NEAR(0.0, distance(original[i], mol.atomPosition3d(i)), 1e-12)
      << "atom " << i;
}

// A torsion is measured between two planes. With c on the a-b axis the
// second plane does not exist, so the measured value is meaningless and no
// rotation could reach the requested one.
TEST(FragmentToolsTest, torsionWithoutASecondPlaneIsRefused)
{
  Molecule m;
  RWMolecule mol(m);
  // a, b and c collinear along x; the moving atom is off the axis.
  mol.addAtom(6, Vector3(0.0, 1.0, 0.0)); // atom, off axis
  mol.addAtom(6, Vector3(0.0, 0.0, 0.0)); // a
  mol.addAtom(6, Vector3(1.2, 0.0, 0.0)); // b
  mol.addAtom(6, Vector3(2.4, 0.0, 0.0)); // c, on the a-b axis
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 1);
  mol.addBond(2, 3, 1);
  const Array<Vector3> original = mol.atomPositions3d();

  EXPECT_FALSE(FragmentTools::setTorsion(mol, 0, 1, 2, 3, 60.0));

  // And with c sitting on top of b, which is the same failure.
  mol.setAtomPosition3d(3, mol.atomPosition3d(2));
  EXPECT_FALSE(FragmentTools::setTorsion(mol, 0, 1, 2, 3, 60.0));

  for (Index i = 0; i < 3; ++i)
    EXPECT_NEAR(0.0, distance(original[i], mol.atomPosition3d(i)), 1e-12)
      << "atom " << i;
}

TEST(FragmentToolsTest, collinearAngleIsRefused)
{
  Molecule m;
  RWMolecule mol(m);
  // Three atoms in a line: there is no plane for the angle to open in.
  mol.addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6, Vector3(1.2, 0.0, 0.0));
  mol.addAtom(6, Vector3(2.4, 0.0, 0.0));
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 1);

  EXPECT_FALSE(FragmentTools::setAngle(mol, 0, 1, 2, 109.5));
  // The distance along that line is still perfectly well defined.
  EXPECT_TRUE(FragmentTools::setDistance(mol, 0, 1, 1.5));
  EXPECT_NEAR(1.5, distance(mol.atomPosition3d(0), mol.atomPosition3d(1)),
              1e-9);
}
