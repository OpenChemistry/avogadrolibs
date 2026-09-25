/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/angletools.h>
#include <avogadro/qtgui/fragmenttools.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <array>
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

// Rotate a vector about the z axis. Used below to lay out a chain of atoms
// in the xy-plane with chosen bond angles between consecutive links.
Vector3 rotateAboutZ(const Vector3& v, Real angle)
{
  return Vector3(v.x() * std::cos(angle) - v.y() * std::sin(angle),
                 v.x() * std::sin(angle) + v.y() * std::cos(angle), 0.0);
}

// Butane's four backbone carbons, laid out as a fully extended zigzag: all
// four stay in the xy-plane, so C1-C2-C3-C4 is a real, non-degenerate
// dihedral (the tests below read back whatever value this construction
// happens to produce rather than assuming a particular number). Each carbon
// also carries hydrogens, placed well clear of the backbone but without
// claiming to be a chemically precise methyl/methylene geometry -- only the
// backbone matters for what these tests check.
struct Butane
{
  Index c1, c2, c3, c4;
};

Butane buildButane(RWMolecule& mol)
{
  const Real cc = 1.54;
  const Real theta = 109.5 * M_PI / 180.0;

  Butane b;
  b.c1 = mol.addAtom(6, Vector3(0.0, 0.0, 0.0)).index();
  b.c2 = mol.addAtom(6, Vector3(cc, 0.0, 0.0)).index();

  const Vector3 p1 = mol.atomPosition3d(b.c1);
  const Vector3 p2 = mol.atomPosition3d(b.c2);
  const Vector3 u12 = (p1 - p2).normalized();   // c2 -> c1
  const Vector3 v23 = rotateAboutZ(u12, theta); // c2 -> c3, angle c1-c2-c3
  const Vector3 p3 = p2 + cc * v23;
  b.c3 = mol.addAtom(6, p3).index();

  const Vector3 u32 = (p2 - p3).normalized();    // c3 -> c2
  const Vector3 v34 = rotateAboutZ(u32, -theta); // c3 -> c4, angle c2-c3-c4
  const Vector3 p4 = p3 + cc * v34;
  b.c4 = mol.addAtom(6, p4).index();

  mol.addBond(b.c1, b.c2, 1);
  mol.addBond(b.c2, b.c3, 1);
  mol.addBond(b.c3, b.c4, 1);

  const auto addHydrogen = [&mol](Index carbon, const Vector3& offset) {
    const Vector3 pos = mol.atomPosition3d(carbon) + offset;
    const Index h = mol.addAtom(1, pos).index();
    mol.addBond(carbon, h, 1);
  };
  addHydrogen(b.c1, Vector3(-0.6, 0.6, 0.6));
  addHydrogen(b.c1, Vector3(-0.6, -0.6, 0.6));
  addHydrogen(b.c1, Vector3(-0.9, 0.0, -0.6));
  addHydrogen(b.c2, Vector3(0.3, -0.9, 0.6));
  addHydrogen(b.c2, Vector3(0.3, -0.9, -0.6));
  addHydrogen(b.c3, Vector3(-0.3, 0.9, 0.6));
  addHydrogen(b.c3, Vector3(-0.3, 0.9, -0.6));
  addHydrogen(b.c4, Vector3(0.6, 0.6, 0.6));
  addHydrogen(b.c4, Vector3(0.6, -0.6, 0.6));
  addHydrogen(b.c4, Vector3(0.9, 0.0, -0.6));

  return b;
}

// The six internal coordinates a Measure tool chain of the four backbone
// atoms would display.
struct ButaneCoordinates
{
  Real d12, d23, d34, a123, a234, t1234;
};

ButaneCoordinates measureButane(RWMolecule& mol, const Butane& b)
{
  const Vector3 p1 = mol.atomPosition3d(b.c1);
  const Vector3 p2 = mol.atomPosition3d(b.c2);
  const Vector3 p3 = mol.atomPosition3d(b.c3);
  const Vector3 p4 = mol.atomPosition3d(b.c4);

  ButaneCoordinates c;
  c.d12 = distance(p1, p2);
  c.d23 = distance(p2, p3);
  c.d34 = distance(p3, p4);
  c.a123 = calculateAngle(p1, p2, p3);
  c.a234 = calculateAngle(p2, p3, p4);
  c.t1234 = calculateDihedral(p1, p2, p3, p4);
  return c;
}

// Checks that every coordinate except the one named just changed -- the
// invariant a Measure tool row edit has to hold for the other rows to stay
// put on screen.
void expectOnlyChanged(const ButaneCoordinates& before,
                       const ButaneCoordinates& after, int changed)
{
  if (changed != 0)
    EXPECT_NEAR(before.d12, after.d12, 1e-6) << "d12 should not have changed";
  if (changed != 1)
    EXPECT_NEAR(before.d23, after.d23, 1e-6) << "d23 should not have changed";
  if (changed != 2)
    EXPECT_NEAR(before.d34, after.d34, 1e-6) << "d34 should not have changed";
  if (changed != 3)
    EXPECT_NEAR(before.a123, after.a123, 1e-6)
      << "a123 should not have changed";
  if (changed != 4)
    EXPECT_NEAR(before.a234, after.a234, 1e-6)
      << "a234 should not have changed";
  if (changed != 5)
    EXPECT_NEAR(before.t1234, after.t1234, 1e-6)
      << "t1234 should not have changed";
}

// Two water molecules with nothing bonding them to each other.
struct WaterDimer
{
  Index o1, h1a, h1b, o2, h2a, h2b;
};

void addWater(RWMolecule& mol, const Vector3& origin, Index& o, Index& ha,
              Index& hb)
{
  const Real oh = 0.96;
  const Real halfAngle = 104.5 * M_PI / 180.0 / 2.0;
  o = mol.addAtom(8, origin).index();
  ha = mol
         .addAtom(1, origin + Vector3(oh * std::sin(halfAngle),
                                      oh * std::cos(halfAngle), 0.0))
         .index();
  hb = mol
         .addAtom(1, origin + Vector3(-oh * std::sin(halfAngle),
                                      oh * std::cos(halfAngle), 0.0))
         .index();
  mol.addBond(o, ha, 1);
  mol.addBond(o, hb, 1);
}

WaterDimer buildWaterDimer(RWMolecule& mol)
{
  WaterDimer w;
  addWater(mol, Vector3(0.0, 0.0, 0.0), w.o1, w.h1a, w.h1b);
  // Offset in y and z, well clear of the first water's plane.
  addWater(mol, Vector3(0.0, 3.5, 1.2), w.o2, w.h2a, w.h2b);
  return w;
}

// A water's own bond lengths and bond angle, to confirm it rode along
// rigidly rather than being distorted by the transform.
struct WaterInternal
{
  Real oh1, oh2, hoh;
};

WaterInternal measureWater(RWMolecule& mol, Index o, Index ha, Index hb)
{
  const Vector3 po = mol.atomPosition3d(o);
  const Vector3 pa = mol.atomPosition3d(ha);
  const Vector3 pb = mol.atomPosition3d(hb);
  WaterInternal w;
  w.oh1 = distance(po, pa);
  w.oh2 = distance(po, pb);
  w.hoh = calculateAngle(pa, po, pb);
  return w;
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

// The key invariant for the Measure tool: setting one of the six chain
// coordinates on a bonded, acyclic chain must reach its target and leave
// the other five exactly where they were.
TEST(FragmentToolsTest, chainEditsOnButaneLeaveTheOtherFiveCoordinatesAlone)
{
  Molecule m;
  RWMolecule mol(m);
  const Butane b = buildButane(mol);

  const Index c1 = mol.atomUniqueId(b.c1);
  const Index c2 = mol.atomUniqueId(b.c2);
  const Index c3 = mol.atomUniqueId(b.c3);
  const Index c4 = mol.atomUniqueId(b.c4);

  const Vector3 c1Position = mol.atomPosition3d(b.c1);
  // c1's three hydrogens were the first three atoms added after the
  // backbone.
  const Vector3 c1H0 = mol.atomPosition3d(4);
  const Vector3 c1H1 = mol.atomPosition3d(5);
  const Vector3 c1H2 = mol.atomPosition3d(6);

  ButaneCoordinates before = measureButane(mol, b);

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainDistance(mol, std::array<Index, 2>{ c1, c2 },
                                            before.d12 + 0.10));
  ButaneCoordinates after = measureButane(mol, b);
  EXPECT_NEAR(before.d12 + 0.10, after.d12, 1e-6);
  expectOnlyChanged(before, after, 0);
  before = after;

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainDistance(mol, std::array<Index, 2>{ c2, c3 },
                                            before.d23 - 0.10));
  after = measureButane(mol, b);
  EXPECT_NEAR(before.d23 - 0.10, after.d23, 1e-6);
  expectOnlyChanged(before, after, 1);
  before = after;

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainDistance(mol, std::array<Index, 2>{ c3, c4 },
                                            before.d34 + 0.05));
  after = measureButane(mol, b);
  EXPECT_NEAR(before.d34 + 0.05, after.d34, 1e-6);
  expectOnlyChanged(before, after, 2);
  before = after;

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainAngle(
              mol, std::array<Index, 3>{ c1, c2, c3 }, 115.0));
  after = measureButane(mol, b);
  EXPECT_NEAR(115.0, after.a123, 1e-6);
  expectOnlyChanged(before, after, 3);
  before = after;

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainAngle(
              mol, std::array<Index, 3>{ c2, c3, c4 }, 105.0));
  after = measureButane(mol, b);
  EXPECT_NEAR(105.0, after.a234, 1e-6);
  expectOnlyChanged(before, after, 4);
  before = after;

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainTorsion(
              mol, std::array<Index, 4>{ c1, c2, c3, c4 }, -60.0));
  after = measureButane(mol, b);
  EXPECT_NEAR(-60.0, after.t1234, 1e-6);
  expectOnlyChanged(before, after, 5);

  // No edit in this sequence ever named c1 as the atom to move, and its
  // hydrogens have no other way to move either.
  EXPECT_NEAR(0.0, distance(c1Position, mol.atomPosition3d(b.c1)), 1e-9);
  EXPECT_NEAR(0.0, distance(c1H0, mol.atomPosition3d(4)), 1e-9);
  EXPECT_NEAR(0.0, distance(c1H1, mol.atomPosition3d(5)), 1e-9);
  EXPECT_NEAR(0.0, distance(c1H2, mol.atomPosition3d(6)), 1e-9);
}

// Reversing the chain moves the invariant to the other end: same six
// values, but now c4 is the one that never moves.
TEST(FragmentToolsTest, chainEditsOnReversedButaneKeepC4Fixed)
{
  Molecule m;
  RWMolecule mol(m);
  const Butane b = buildButane(mol);

  const Index c1 = mol.atomUniqueId(b.c1);
  const Index c2 = mol.atomUniqueId(b.c2);
  const Index c3 = mol.atomUniqueId(b.c3);
  const Index c4 = mol.atomUniqueId(b.c4);

  const Vector3 c4Position = mol.atomPosition3d(b.c4);
  // c4's three hydrogens were the last three atoms added.
  const Index h0Index = mol.atomCount() - 3;
  const Index h1Index = mol.atomCount() - 2;
  const Index h2Index = mol.atomCount() - 1;
  const Vector3 c4H0 = mol.atomPosition3d(h0Index);
  const Vector3 c4H1 = mol.atomPosition3d(h1Index);
  const Vector3 c4H2 = mol.atomPosition3d(h2Index);

  ButaneCoordinates before = measureButane(mol, b);

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainDistance(mol, std::array<Index, 2>{ c4, c3 },
                                            before.d34 + 0.10));
  ButaneCoordinates after = measureButane(mol, b);
  EXPECT_NEAR(before.d34 + 0.10, after.d34, 1e-6);
  expectOnlyChanged(before, after, 2);
  before = after;

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainDistance(mol, std::array<Index, 2>{ c3, c2 },
                                            before.d23 - 0.10));
  after = measureButane(mol, b);
  EXPECT_NEAR(before.d23 - 0.10, after.d23, 1e-6);
  expectOnlyChanged(before, after, 1);
  before = after;

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainDistance(mol, std::array<Index, 2>{ c2, c1 },
                                            before.d12 + 0.05));
  after = measureButane(mol, b);
  EXPECT_NEAR(before.d12 + 0.05, after.d12, 1e-6);
  expectOnlyChanged(before, after, 0);
  before = after;

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainAngle(
              mol, std::array<Index, 3>{ c4, c3, c2 }, 105.0));
  after = measureButane(mol, b);
  EXPECT_NEAR(105.0, after.a234, 1e-6);
  expectOnlyChanged(before, after, 4);
  before = after;

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainAngle(
              mol, std::array<Index, 3>{ c3, c2, c1 }, 115.0));
  after = measureButane(mol, b);
  EXPECT_NEAR(115.0, after.a123, 1e-6);
  expectOnlyChanged(before, after, 3);
  before = after;

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainTorsion(
              mol, std::array<Index, 4>{ c4, c3, c2, c1 }, -60.0));
  after = measureButane(mol, b);
  EXPECT_NEAR(-60.0, after.t1234, 1e-6);
  expectOnlyChanged(before, after, 5);

  EXPECT_NEAR(0.0, distance(c4Position, mol.atomPosition3d(b.c4)), 1e-9);
  EXPECT_NEAR(0.0, distance(c4H0, mol.atomPosition3d(h0Index)), 1e-9);
  EXPECT_NEAR(0.0, distance(c4H1, mol.atomPosition3d(h1Index)), 1e-9);
  EXPECT_NEAR(0.0, distance(c4H2, mol.atomPosition3d(h2Index)), 1e-9);
}

// An internal coordinate across a water dimer's two separate molecules has
// nothing on the anchor's side to hold the far end in place, so the whole
// of the other water comes along rigidly. Four different chain shapes,
// straight from the design table.
TEST(FragmentToolsTest, chainDistanceAcrossAWaterDimerMovesWaterTwoRigidly)
{
  Molecule m;
  RWMolecule mol(m);
  const WaterDimer w = buildWaterDimer(mol);

  const Index o1 = mol.atomUniqueId(w.o1);
  const Index h2a = mol.atomUniqueId(w.h2a);

  const Vector3 water1O = mol.atomPosition3d(w.o1);
  const Vector3 water1Ha = mol.atomPosition3d(w.h1a);
  const Vector3 water1Hb = mol.atomPosition3d(w.h1b);
  const WaterInternal before2 = measureWater(mol, w.o2, w.h2a, w.h2b);

  ASSERT_EQ(
    FragmentTools::CoordinateEditResult::Ok,
    FragmentTools::setChainDistance(mol, std::array<Index, 2>{ o1, h2a }, 2.0));

  EXPECT_NEAR(
    2.0, distance(mol.atomPosition3d(w.o1), mol.atomPosition3d(w.h2a)), 1e-6);

  EXPECT_NEAR(0.0, distance(water1O, mol.atomPosition3d(w.o1)), 1e-9);
  EXPECT_NEAR(0.0, distance(water1Ha, mol.atomPosition3d(w.h1a)), 1e-9);
  EXPECT_NEAR(0.0, distance(water1Hb, mol.atomPosition3d(w.h1b)), 1e-9);

  const WaterInternal after2 = measureWater(mol, w.o2, w.h2a, w.h2b);
  EXPECT_NEAR(before2.oh1, after2.oh1, 1e-9);
  EXPECT_NEAR(before2.oh2, after2.oh2, 1e-9);
  EXPECT_NEAR(before2.hoh, after2.hoh, 1e-9);
}

TEST(FragmentToolsTest, chainAngleWithVertexInWaterOneMovesWaterTwoRigidly)
{
  Molecule m;
  RWMolecule mol(m);
  const WaterDimer w = buildWaterDimer(mol);

  // O-H...O': the vertex is H, in water 1.
  const Index o1 = mol.atomUniqueId(w.o1);
  const Index h1a = mol.atomUniqueId(w.h1a);
  const Index o2 = mol.atomUniqueId(w.o2);

  const Vector3 water1O = mol.atomPosition3d(w.o1);
  const Vector3 water1Ha = mol.atomPosition3d(w.h1a);
  const Vector3 water1Hb = mol.atomPosition3d(w.h1b);
  const WaterInternal before2 = measureWater(mol, w.o2, w.h2a, w.h2b);

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainAngle(
              mol, std::array<Index, 3>{ o1, h1a, o2 }, 130.0));

  EXPECT_NEAR(130.0,
              calculateAngle(mol.atomPosition3d(w.o1),
                             mol.atomPosition3d(w.h1a),
                             mol.atomPosition3d(w.o2)),
              1e-6);

  EXPECT_NEAR(0.0, distance(water1O, mol.atomPosition3d(w.o1)), 1e-9);
  EXPECT_NEAR(0.0, distance(water1Ha, mol.atomPosition3d(w.h1a)), 1e-9);
  EXPECT_NEAR(0.0, distance(water1Hb, mol.atomPosition3d(w.h1b)), 1e-9);

  const WaterInternal after2 = measureWater(mol, w.o2, w.h2a, w.h2b);
  EXPECT_NEAR(before2.oh1, after2.oh1, 1e-9);
  EXPECT_NEAR(before2.oh2, after2.oh2, 1e-9);
  EXPECT_NEAR(before2.hoh, after2.hoh, 1e-9);
}

TEST(FragmentToolsTest, chainAngleWithVertexInWaterTwoMovesWaterTwoRigidly)
{
  Molecule m;
  RWMolecule mol(m);
  const WaterDimer w = buildWaterDimer(mol);

  // H...O'-H': the vertex is O', in water 2.
  const Index h1a = mol.atomUniqueId(w.h1a);
  const Index o2 = mol.atomUniqueId(w.o2);
  const Index h2a = mol.atomUniqueId(w.h2a);

  const Vector3 water1O = mol.atomPosition3d(w.o1);
  const Vector3 water1Ha = mol.atomPosition3d(w.h1a);
  const Vector3 water1Hb = mol.atomPosition3d(w.h1b);
  const WaterInternal before2 = measureWater(mol, w.o2, w.h2a, w.h2b);

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainAngle(
              mol, std::array<Index, 3>{ h1a, o2, h2a }, 95.0));

  EXPECT_NEAR(95.0,
              calculateAngle(mol.atomPosition3d(w.h1a),
                             mol.atomPosition3d(w.o2),
                             mol.atomPosition3d(w.h2a)),
              1e-6);

  EXPECT_NEAR(0.0, distance(water1O, mol.atomPosition3d(w.o1)), 1e-9);
  EXPECT_NEAR(0.0, distance(water1Ha, mol.atomPosition3d(w.h1a)), 1e-9);
  EXPECT_NEAR(0.0, distance(water1Hb, mol.atomPosition3d(w.h1b)), 1e-9);

  const WaterInternal after2 = measureWater(mol, w.o2, w.h2a, w.h2b);
  EXPECT_NEAR(before2.oh1, after2.oh1, 1e-9);
  EXPECT_NEAR(before2.oh2, after2.oh2, 1e-9);
  EXPECT_NEAR(before2.hoh, after2.hoh, 1e-9);
}

TEST(FragmentToolsTest, chainTorsionAcrossAWaterDimerMovesWaterTwoRigidly)
{
  Molecule m;
  RWMolecule mol(m);
  const WaterDimer w = buildWaterDimer(mol);

  // H-O...O'-H'.
  const Index h1a = mol.atomUniqueId(w.h1a);
  const Index o1 = mol.atomUniqueId(w.o1);
  const Index o2 = mol.atomUniqueId(w.o2);
  const Index h2a = mol.atomUniqueId(w.h2a);

  const Vector3 water1O = mol.atomPosition3d(w.o1);
  const Vector3 water1Ha = mol.atomPosition3d(w.h1a);
  const Vector3 water1Hb = mol.atomPosition3d(w.h1b);
  const WaterInternal before2 = measureWater(mol, w.o2, w.h2a, w.h2b);

  ASSERT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainTorsion(
              mol, std::array<Index, 4>{ h1a, o1, o2, h2a }, 45.0));

  EXPECT_NEAR(
    45.0,
    calculateDihedral(mol.atomPosition3d(w.h1a), mol.atomPosition3d(w.o1),
                      mol.atomPosition3d(w.o2), mol.atomPosition3d(w.h2a)),
    1e-6);

  EXPECT_NEAR(0.0, distance(water1O, mol.atomPosition3d(w.o1)), 1e-9);
  EXPECT_NEAR(0.0, distance(water1Ha, mol.atomPosition3d(w.h1a)), 1e-9);
  EXPECT_NEAR(0.0, distance(water1Hb, mol.atomPosition3d(w.h1b)), 1e-9);

  const WaterInternal after2 = measureWater(mol, w.o2, w.h2a, w.h2b);
  EXPECT_NEAR(before2.oh1, after2.oh1, 1e-9);
  EXPECT_NEAR(before2.oh2, after2.oh2, 1e-9);
  EXPECT_NEAR(before2.hoh, after2.hoh, 1e-9);
}

// The default (fragment-free) overload is the z-matrix path, and it now
// picks up the same different-component rule: naming an atom in the second
// water moves that whole water, not just the named atom.
TEST(FragmentToolsTest, defaultSetDistanceAcrossAWaterDimerMovesWaterTwoWhole)
{
  Molecule m;
  RWMolecule mol(m);
  const WaterDimer w = buildWaterDimer(mol);

  const Vector3 water1O = mol.atomPosition3d(w.o1);
  const Vector3 water1Ha = mol.atomPosition3d(w.h1a);
  const Vector3 water1Hb = mol.atomPosition3d(w.h1b);
  const Vector3 h2aOriginal = mol.atomPosition3d(w.h2a);
  const WaterInternal before2 = measureWater(mol, w.o2, w.h2a, w.h2b);

  // O' moves, H (in water 1) anchors -- the z-matrix convention where the
  // first-named atom is the one a row places.
  ASSERT_TRUE(FragmentTools::setDistance(mol, w.o2, w.h1a, 2.5));

  EXPECT_NEAR(
    2.5, distance(mol.atomPosition3d(w.o2), mol.atomPosition3d(w.h1a)), 1e-6);

  EXPECT_NEAR(0.0, distance(water1O, mol.atomPosition3d(w.o1)), 1e-9);
  EXPECT_NEAR(0.0, distance(water1Ha, mol.atomPosition3d(w.h1a)), 1e-9);
  EXPECT_NEAR(0.0, distance(water1Hb, mol.atomPosition3d(w.h1b)), 1e-9);

  // The whole molecule moved, not just the named atom.
  EXPECT_GT(distance(h2aOriginal, mol.atomPosition3d(w.h2a)), 1e-6);

  const WaterInternal after2 = measureWater(mol, w.o2, w.h2a, w.h2b);
  EXPECT_NEAR(before2.oh1, after2.oh1, 1e-9);
  EXPECT_NEAR(before2.oh2, after2.oh2, 1e-9);
  EXPECT_NEAR(before2.hoh, after2.hoh, 1e-9);
}

// A fragment that carries its own fixed reference along would turn the edit
// into a silent no-op, so the guard refuses it outright instead.
TEST(FragmentToolsTest, fragmentContainingTheFixedReferenceIsRefused)
{
  Molecule m;
  RWMolecule mol(m);
  buildEthane(mol);
  const Array<Vector3> original = mol.atomPositions3d();

  Array<Index> everyAtom;
  for (Index i = 0; i < mol.atomCount(); ++i)
    everyAtom.push_back(mol.atomUniqueId(i));

  EXPECT_FALSE(FragmentTools::setDistance(mol, 1, 0, 2.0, everyAtom));
  EXPECT_FALSE(FragmentTools::setAngle(mol, 5, 1, 0, 100.0, everyAtom));
  EXPECT_FALSE(FragmentTools::setTorsion(mol, 5, 1, 0, 2, 60.0, everyAtom));

  for (Index i = 0; i < mol.atomCount(); ++i)
    EXPECT_NEAR(0.0, distance(original[i], mol.atomPosition3d(i)), 1e-12)
      << "atom " << i;
}

// Two ring atoms with a common bonded neighbour, but not bonded to each
// other: the vertex's side of the bonded arm cannot reach the far atom
// without going the other way around the ring, so there is no bond-side
// fragment that works.
TEST(FragmentToolsTest, chainAngleAcrossARingIsRefused)
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

  const Index a0 = mol.atomUniqueId(0);
  const Index a1 = mol.atomUniqueId(1);
  const Index a3 = mol.atomUniqueId(3);

  EXPECT_EQ(FragmentTools::CoordinateEditResult::Ring,
            FragmentTools::setChainAngle(
              mol, std::array<Index, 3>{ a0, a1, a3 }, 100.0));

  for (Index i = 0; i < mol.atomCount(); ++i)
    EXPECT_NEAR(0.0, distance(original[i], mol.atomPosition3d(i)), 1e-12)
      << "atom " << i;
}

// i-j unbonded, j-k bonded: the fragment (k's side of the j-k bond) always
// contains k itself, so the only way setAngle() can refuse it is the
// fixed-reference guard -- here because k's side also reaches all the way
// back to i by another route. That is a rigidity problem, not a ring, and
// must be reported as NotRigid rather than Ring.
TEST(FragmentToolsTest,
     chainAngleWithNoFirstBondAndAFixedReferenceOnTheSecondIsNotRigid)
{
  Molecule m;
  RWMolecule mol(m);
  // The same bent, three-atom shape as the propane distance test below
  // (bonds 0-1 and 1-2, no 0-2 bond), but read as an angle with the chain
  // reordered so the vertex (j) is atom 0 and the moving end (k) is atom 1:
  // i-j (atom2-atom0) is unbonded, j-k (atom0-atom1) is bonded, and k's side
  // of that bond -- atoms 1 and 2, since 1-2 is also bonded -- reaches all
  // the way to i (atom2).
  const Real cc = 1.54;
  const Real theta = 109.5 * M_PI / 180.0;
  mol.addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6, Vector3(cc, 0.0, 0.0));
  const Vector3 u = Vector3(-1.0, 0.0, 0.0);
  const Vector3 v = rotateAboutZ(u, theta);
  mol.addAtom(6, Vector3(cc, 0.0, 0.0) + cc * v);
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 1);
  const Array<Vector3> original = mol.atomPositions3d();

  const Index a0 = mol.atomUniqueId(0);
  const Index a1 = mol.atomUniqueId(1);
  const Index a2 = mol.atomUniqueId(2);

  EXPECT_EQ(FragmentTools::CoordinateEditResult::NotRigid,
            FragmentTools::setChainAngle(
              mol, std::array<Index, 3>{ a2, a0, a1 }, 100.0));

  for (Index i = 0; i < mol.atomCount(); ++i)
    EXPECT_NEAR(0.0, distance(original[i], mol.atomPosition3d(i)), 1e-12)
      << "atom " << i;
}

// A ring bond length is not refused the way a ring angle is: the chain API
// stretches it the same way the bond table always has, moving the named atom
// and leaving the rest of the ring where it was.
TEST(FragmentToolsTest, chainDistanceAlongARingBondIsAllowed)
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

  EXPECT_EQ(FragmentTools::CoordinateEditResult::Ok,
            FragmentTools::setChainDistance(
              mol,
              std::array<Index, 2>{ mol.atomUniqueId(0), mol.atomUniqueId(1) },
              1.54));

  EXPECT_NEAR(1.54, distance(mol.atomPosition3d(0), mol.atomPosition3d(1)),
              1e-9);
  for (Index i = 0; i < mol.atomCount(); ++i) {
    if (i != 1)
      EXPECT_NEAR(0.0, distance(original[i], mol.atomPosition3d(i)), 1e-12)
        << "atom " << i;
  }
}

// The two end carbons of propane share a molecule but are not bonded, and
// the only bonds involved (C1-C2, C2-C3) both keep the whole molecule
// together, so there is no rigid side to move independently.
TEST(FragmentToolsTest, chainDistanceAcrossPropaneOneThreeIsNotRigid)
{
  Molecule m;
  RWMolecule mol(m);
  const Real cc = 1.54;
  const Real theta = 109.5 * M_PI / 180.0;
  mol.addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol.addAtom(6, Vector3(cc, 0.0, 0.0));
  const Vector3 u = Vector3(-1.0, 0.0, 0.0);
  const Vector3 v = rotateAboutZ(u, theta);
  mol.addAtom(6, Vector3(cc, 0.0, 0.0) + cc * v);
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 1);
  const Array<Vector3> original = mol.atomPositions3d();

  const Index a0 = mol.atomUniqueId(0);
  const Index a2 = mol.atomUniqueId(2);

  EXPECT_EQ(
    FragmentTools::CoordinateEditResult::NotRigid,
    FragmentTools::setChainDistance(mol, std::array<Index, 2>{ a0, a2 }, 3.0));

  for (Index i = 0; i < mol.atomCount(); ++i)
    EXPECT_NEAR(0.0, distance(original[i], mol.atomPosition3d(i)), 1e-12)
      << "atom " << i;
}

// A chain edit is one undo step, the same as the fragment-free overloads.
TEST(FragmentToolsTest, chainEditIsASingleUndoStep)
{
  Molecule m;
  RWMolecule mol(m);
  buildEthane(mol);
  const int before = mol.undoStack().count();
  const Array<Vector3> original = mol.atomPositions3d();

  const Index a0 = mol.atomUniqueId(0);
  const Index a1 = mol.atomUniqueId(1);

  ASSERT_EQ(
    FragmentTools::CoordinateEditResult::Ok,
    FragmentTools::setChainDistance(mol, std::array<Index, 2>{ a0, a1 }, 2.0));
  EXPECT_EQ(before + 1, mol.undoStack().count());

  mol.undoStack().undo();
  for (Index i = 0; i < mol.atomCount(); ++i)
    EXPECT_NEAR(0.0, distance(original[i], mol.atomPosition3d(i)), 1e-9)
      << "atom " << i;
}
