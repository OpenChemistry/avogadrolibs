/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <algorithm>

using namespace Avogadro;
using namespace Avogadro::Core;

namespace {

// A 5 Angstrom cubic cell holding a carbon at the origin and an oxygen at the
// body centre, bonded to each other.
Molecule cubicCell()
{
  Molecule mol;
  mol.setUnitCell(new UnitCell(Vector3(5.0, 0.0, 0.0), Vector3(0.0, 5.0, 0.0),
                               Vector3(0.0, 0.0, 5.0)));
  Atom c = mol.addAtom(6);
  c.setPosition3d(Vector3(0.0, 0.0, 0.0));
  Atom o = mol.addAtom(8);
  o.setPosition3d(Vector3(2.5, 2.5, 2.5));
  mol.addBond(c, o, 1);
  return mol;
}

// Counts the atoms whose fractional coordinates match @a frac.
Index countAtomsAt(const Molecule& mol, const Vector3& frac)
{
  Index count = 0;
  for (Index i = 0; i < mol.atomCount(); ++i) {
    if ((mol.unitCell()->toFractional(mol.atomPosition3d(i)) - frac).norm() <
        1e-4) {
      ++count;
    }
  }
  return count;
}

} // namespace

TEST(CrystalToolsTest, buildSupercellIntegerRepeats)
{
  Molecule mol = cubicCell();
  EXPECT_TRUE(CrystalTools::buildSupercell(mol, 2, 1, 1));

  EXPECT_EQ(mol.atomCount(), 4);
  EXPECT_EQ(mol.bondCount(), 2);
  EXPECT_NEAR(mol.unitCell()->a(), 10.0, 1e-6);
  EXPECT_NEAR(mol.unitCell()->b(), 5.0, 1e-6);
  EXPECT_NEAR(mol.unitCell()->c(), 5.0, 1e-6);
}

TEST(CrystalToolsTest, buildSupercellRejectsBadInput)
{
  Molecule mol = cubicCell();
  EXPECT_FALSE(CrystalTools::buildSupercell(mol, 0, 1, 1));
  // An empty range along any axis would leave nothing behind.
  EXPECT_FALSE(CrystalTools::buildSupercell(mol, Vector3(0.0, 0.0, 0.0),
                                            Vector3(0.0, 1.0, 1.0)));
  EXPECT_FALSE(CrystalTools::buildSupercell(mol, Vector3(0.0, 0.0, 0.0),
                                            Vector3(1.0, 1.0, -1.0)));
  // Nothing should have changed.
  EXPECT_EQ(mol.atomCount(), 2);

  // No unit cell at all.
  Molecule noCell;
  EXPECT_FALSE(CrystalTools::buildSupercell(noCell, Vector3(0.0, 0.0, 0.0),
                                            Vector3(1.0, 1.0, 1.0)));
}

// An integer range must give exactly the same result as the integer form.
TEST(CrystalToolsTest, buildSupercellIntegerRangeMatchesRepeats)
{
  Molecule repeats = cubicCell();
  CrystalTools::buildSupercell(repeats, 2, 3, 1);

  Molecule range = cubicCell();
  EXPECT_TRUE(CrystalTools::buildSupercell(range, Vector3(0.0, 0.0, 0.0),
                                           Vector3(2.0, 3.0, 1.0)));

  ASSERT_EQ(range.atomCount(), repeats.atomCount());
  EXPECT_EQ(range.bondCount(), repeats.bondCount());
  for (Index i = 0; i < repeats.atomCount(); ++i) {
    EXPECT_EQ(range.atomicNumber(i), repeats.atomicNumber(i));
    EXPECT_LT((range.atomPosition3d(i) - repeats.atomPosition3d(i)).norm(),
              1e-6);
  }
  EXPECT_NEAR(range.unitCell()->a(), repeats.unitCell()->a(), 1e-6);
  EXPECT_NEAR(range.unitCell()->b(), repeats.unitCell()->b(), 1e-6);
  EXPECT_NEAR(range.unitCell()->c(), repeats.unitCell()->c(), 1e-6);
}

// A negative integer range is still a supercell; the atoms are shifted so that
// the lower limit lands on the new origin.
TEST(CrystalToolsTest, buildSupercellIntegerRangeShiftsOrigin)
{
  Molecule mol = cubicCell();
  EXPECT_TRUE(CrystalTools::buildSupercell(mol, Vector3(-1.0, 0.0, 0.0),
                                           Vector3(1.0, 1.0, 1.0)));

  EXPECT_EQ(mol.atomCount(), 4);
  EXPECT_EQ(mol.bondCount(), 2);
  EXPECT_NEAR(mol.unitCell()->a(), 10.0, 1e-6);

  // Every atom must sit inside the new cell, and the -1 subcell must have been
  // moved to the origin.
  for (Index i = 0; i < mol.atomCount(); ++i) {
    Vector3 frac = mol.unitCell()->toFractional(mol.atomPosition3d(i));
    EXPECT_GE(frac.x(), -1e-6);
    EXPECT_LE(frac.x(), 1.0 + 1e-6);
  }
  EXPECT_EQ(countAtomsAt(mol, Vector3(0.0, 0.0, 0.0)), 1);
  EXPECT_EQ(countAtomsAt(mol, Vector3(0.5, 0.0, 0.0)), 1);
}

// A fractional range is a packing view: the cell is untouched and the copies
// extend beyond it.
TEST(CrystalToolsTest, buildSupercellFractionalRangeKeepsCell)
{
  Molecule mol = cubicCell();
  EXPECT_TRUE(CrystalTools::buildSupercell(mol, Vector3(-0.5, -0.5, -0.5),
                                           Vector3(0.5, 0.5, 0.5)));

  // The cell is left alone so that it still describes a real lattice.
  EXPECT_NEAR(mol.unitCell()->a(), 5.0, 1e-6);
  EXPECT_NEAR(mol.unitCell()->b(), 5.0, 1e-6);
  EXPECT_NEAR(mol.unitCell()->c(), 5.0, 1e-6);

  // The carbon at the origin has only one image in [-0.5, 0.5]; the oxygen at
  // the body centre has one in each of the eight octants.
  EXPECT_EQ(mol.atomCount(), 9);
  EXPECT_EQ(countAtomsAt(mol, Vector3(0.0, 0.0, 0.0)), 1);
  EXPECT_EQ(countAtomsAt(mol, Vector3(-0.5, -0.5, -0.5)), 1);
  EXPECT_EQ(countAtomsAt(mol, Vector3(0.5, 0.5, 0.5)), 1);

  // Only the untranslated copy has both bonded atoms present.
  EXPECT_EQ(mol.bondCount(), 1);
}

// The fractional range is closed, so atoms sitting on a bounding face appear on
// both faces - the usual crystal packing convention.
TEST(CrystalToolsTest, buildSupercellFractionalRangeIncludesBoundaries)
{
  Molecule mol = cubicCell();
  EXPECT_TRUE(CrystalTools::buildSupercell(mol, Vector3(0.0, 0.0, 0.0),
                                           Vector3(1.5, 1.0, 1.0)));

  EXPECT_NEAR(mol.unitCell()->a(), 5.0, 1e-6);

  // The carbon sits on a corner, so it is repeated on all 2x2x2 corners of the
  // 0-1 box plus the two corners at a = 1 ... giving 8 copies; the oxygen at
  // (0.5, 0.5, 0.5) fits at a = 0.5 and a = 1.5 only.
  EXPECT_EQ(mol.atomCount(), 10);
  EXPECT_EQ(countAtomsAt(mol, Vector3(1.0, 1.0, 1.0)), 1);
  EXPECT_EQ(countAtomsAt(mol, Vector3(1.5, 0.5, 0.5)), 1);
  // Nothing beyond the requested range.
  EXPECT_EQ(countAtomsAt(mol, Vector3(2.0, 0.0, 0.0)), 0);

  EXPECT_EQ(mol.bondCount(), 2);
}

// Atoms that coincide after translation (fractional 0.0 and 1.0 are the same
// site) must be merged rather than stacked.
TEST(CrystalToolsTest, buildSupercellMergesDuplicateAtoms)
{
  Molecule mol;
  mol.setUnitCell(new UnitCell(Vector3(5.0, 0.0, 0.0), Vector3(0.0, 5.0, 0.0),
                               Vector3(0.0, 0.0, 5.0)));
  Atom a = mol.addAtom(6);
  a.setPosition3d(Vector3(0.0, 0.0, 0.0));
  Atom b = mol.addAtom(6); // the same site, expressed at fractional 1.0
  b.setPosition3d(Vector3(5.0, 0.0, 0.0));
  Atom c = mol.addAtom(7);
  c.setPosition3d(Vector3(1.0, 2.0, 3.0));
  mol.addBond(a, c, 1);
  mol.addBond(b, c, 2);

  EXPECT_TRUE(CrystalTools::buildSupercell(mol, 3, 1, 1));

  // 3 carbons at a = 0, 5, 10 and 15 (4 sites) plus 3 nitrogens, not 9 atoms.
  EXPECT_EQ(mol.atomCount(), 7);
  EXPECT_EQ(mol.bondCount(), 6);
}

namespace {

// A CO unit split across the a boundary: 1.0 Angstrom apart under periodic
// boundary conditions, but 9.0 Angstrom apart in plain Cartesian space.
Molecule splitAcrossBoundary(bool withBond)
{
  Molecule mol;
  mol.setUnitCell(new UnitCell(Vector3(10.0, 0.0, 0.0), Vector3(0.0, 10.0, 0.0),
                               Vector3(0.0, 0.0, 10.0)));
  Atom c = mol.addAtom(6);
  c.setPosition3d(Vector3(9.5, 5.0, 5.0));
  Atom o = mol.addAtom(8);
  o.setPosition3d(Vector3(0.5, 5.0, 5.0));
  if (withBond)
    mol.addBond(c, o, 2);
  return mol;
}

// Length of the longest bond in @a mol, which is what gives away a bond left
// stretched across the cell.
Real longestBond(const Molecule& mol)
{
  Real longest = 0.0;
  for (Index i = 0; i < mol.bondCount(); ++i) {
    const Bond bond = mol.bond(i);
    longest = std::max(
      longest, (bond.atom1().position3d() - bond.atom2().position3d()).norm());
  }
  return longest;
}

} // namespace

TEST(CrystalToolsTest, perceivePeriodicBondsFindsCrossingBond)
{
  // Nothing bonds these two in Cartesian space, but they are neighbours across
  // the a boundary.
  Molecule mol = splitAcrossBoundary(false);
  EXPECT_EQ(mol.bondCount(), 0);

  Array<CrystalTools::PeriodicBond> bonds =
    CrystalTools::perceivePeriodicBonds(mol);

  ASSERT_EQ(bonds.size(), 1);
  EXPECT_EQ(bonds[0].atom1, 0);
  EXPECT_EQ(bonds[0].atom2, 1);
  EXPECT_EQ(bonds[0].offset, Vector3i(1, 0, 0));
  EXPECT_EQ(bonds[0].order, 1);
  EXPECT_TRUE(bonds[0].perceived);
}

TEST(CrystalToolsTest, perceivePeriodicBondsRoutesStretchedBond)
{
  // The same pair, this time with the stretched bond already in the file. It
  // keeps its order and gains the offset that makes it short.
  Molecule mol = splitAcrossBoundary(true);
  Array<CrystalTools::PeriodicBond> bonds =
    CrystalTools::perceivePeriodicBonds(mol);

  ASSERT_EQ(bonds.size(), 1);
  EXPECT_EQ(bonds[0].offset, Vector3i(1, 0, 0));
  EXPECT_EQ(bonds[0].order, 2);
  EXPECT_FALSE(bonds[0].perceived);
}

// A bond can reach past the half-cell mark without crossing a boundary when an
// axis is short - rutile's c axis is 2.96 Angstrom, less than two Ti-O bonds -
// so the nearest image is not on its own a safe test for rerouting.
TEST(CrystalToolsTest, perceivePeriodicBondsLeavesShortAxisBondAlone)
{
  Molecule mol;
  mol.setUnitCell(new UnitCell(Vector3(10.0, 0.0, 0.0), Vector3(0.0, 10.0, 0.0),
                               Vector3(0.0, 0.0, 3.0)));
  Atom a = mol.addAtom(22); // Ti, covalent radius 1.60
  a.setPosition3d(Vector3(5.0, 5.0, 0.0));
  Atom b = mol.addAtom(22);
  b.setPosition3d(Vector3(5.0, 5.0, 1.9)); // past c/2, but a plausible bond
  mol.addBond(a, b, 1);

  Array<CrystalTools::PeriodicBond> bonds =
    CrystalTools::perceivePeriodicBonds(mol);

  ASSERT_GE(bonds.size(), 1);
  EXPECT_FALSE(bonds[0].perceived);
  EXPECT_EQ(bonds[0].offset, Vector3i(0, 0, 0));
}

TEST(CrystalToolsTest, perceivePeriodicBondsWithoutCell)
{
  Molecule mol;
  Atom a = mol.addAtom(6);
  a.setPosition3d(Vector3(0.0, 0.0, 0.0));
  Atom b = mol.addAtom(8);
  b.setPosition3d(Vector3(1.2, 0.0, 0.0));
  mol.addBond(a, b, 3);

  Array<CrystalTools::PeriodicBond> bonds =
    CrystalTools::perceivePeriodicBonds(mol);

  ASSERT_EQ(bonds.size(), 1);
  EXPECT_EQ(bonds[0].offset, Vector3i(0, 0, 0));
  EXPECT_EQ(bonds[0].order, 3);
  EXPECT_FALSE(bonds[0].perceived);
}

TEST(CrystalToolsTest, buildSupercellJoinsCopiesAcrossBoundary)
{
  // Without the option the two copies stay unbonded, as before.
  Molecule plain = splitAcrossBoundary(false);
  EXPECT_TRUE(CrystalTools::buildSupercell(plain, 2, 1, 1));
  EXPECT_EQ(plain.bondCount(), 0);

  // With it, the halves either side of the boundary are joined.
  Molecule joined = splitAcrossBoundary(false);
  EXPECT_TRUE(CrystalTools::buildSupercell(
    joined, 2, 1, 1, CrystalTools::PerceivePeriodicBonds));
  EXPECT_EQ(joined.atomCount(), 4);
  ASSERT_EQ(joined.bondCount(), 1);
  EXPECT_NEAR(longestBond(joined), 1.0, 1e-6);
}

// A bond the molecule already had must never be dropped, even where the copy it
// points at falls outside the range.
TEST(CrystalToolsTest, buildSupercellKeepsExistingBondsAtRangeEdge)
{
  Molecule mol = splitAcrossBoundary(true);
  EXPECT_TRUE(CrystalTools::buildSupercell(
    mol, 1, 1, 1, CrystalTools::PerceivePeriodicBonds));
  EXPECT_EQ(mol.atomCount(), 2);
  EXPECT_EQ(mol.bondCount(), 1);

  // Two copies: one bond becomes short, the outer one still has to wrap.
  Molecule two = splitAcrossBoundary(true);
  EXPECT_TRUE(CrystalTools::buildSupercell(
    two, 2, 1, 1, CrystalTools::PerceivePeriodicBonds));
  EXPECT_EQ(two.bondCount(), 2);
  EXPECT_EQ(two.bondOrders()[0], 2); // the order survives the rerouting
}

// A perceived bond is only added where both ends are actually present, so a
// packing view stays cut at its outer faces instead of growing spurious bonds.
TEST(CrystalToolsTest, buildSupercellPackingLeavesOuterFacesCut)
{
  Molecule mol = splitAcrossBoundary(false);
  EXPECT_TRUE(CrystalTools::buildSupercell(
    mol, Vector3(0.0, 0.0, 0.0), Vector3(2.5, 1.0, 1.0),
    CrystalTools::PerceivePeriodicBonds));

  // Carbon at 0.95 and 1.95; oxygen at 0.05, 1.05 and 2.05.
  EXPECT_EQ(mol.atomCount(), 5);
  // Both carbons find their oxygen; nothing reaches past the range.
  EXPECT_EQ(mol.bondCount(), 2);
  EXPECT_NEAR(longestBond(mol), 1.0, 1e-6);
}
