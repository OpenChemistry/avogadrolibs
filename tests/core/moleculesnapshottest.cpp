/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/constraint.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/moleculesnapshot.h>
#include <avogadro/core/residue.h>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

using Avogadro::Index;
using Avogadro::MaxIndex;
using Avogadro::Vector3;
using Avogadro::Vector3ub;
using Avogadro::Core::Array;
using Avogadro::Core::AtomSnapshot;
using Avogadro::Core::BondSnapshot;
using Avogadro::Core::Constraint;
using Avogadro::Core::Molecule;
using Avogadro::Core::Residue;

namespace {

const char* kAtomKey = "snap-atom";
const char* kBondKey = "snap-bond";

std::pair<Index, Index> sortedPair(const std::pair<Index, Index>& pair)
{
  return { std::min(pair.first, pair.second),
           std::max(pair.first, pair.second) };
}

// Everything restoring a snapshot has to bring back, compared through the
// public getters. Calculated results are not compared.
::testing::AssertionResult sameMolecule(const Molecule& expected,
                                        const Molecule& got)
{
  auto fail = [](const std::string& what, Index index) {
    return ::testing::AssertionFailure()
           << what << " differs at index " << index;
  };
  if (expected.atomCount() != got.atomCount())
    return fail("atomCount", 0);
  if (expected.bondCount() != got.bondCount())
    return fail("bondCount", 0);
  if (expected.elements() != got.elements())
    return fail("elements", 0);
  if (expected.coordinate3dCount() != got.coordinate3dCount())
    return fail("coordinate3dCount", 0);

  for (Index i = 0; i < expected.atomCount(); ++i) {
    if (expected.atomicNumber(i) != got.atomicNumber(i))
      return fail("atomicNumber", i);
    if (expected.atomPosition3d(i) != got.atomPosition3d(i))
      return fail("position3d", i);
    if (expected.atomPosition2d(i) != got.atomPosition2d(i))
      return fail("position2d", i);
    if (expected.atomLabel(i) != got.atomLabel(i))
      return fail("label", i);
    if (expected.formalCharge(i) != got.formalCharge(i))
      return fail("formalCharge", i);
    if (expected.hybridization(i) != got.hybridization(i))
      return fail("hybridization", i);
    if (expected.isotope(i) != got.isotope(i))
      return fail("isotope", i);
    if (expected.occupancy(i) != got.occupancy(i))
      return fail("occupancy", i);
    if (expected.disorderAssembly(i) != got.disorderAssembly(i))
      return fail("disorderAssembly", i);
    if (expected.disorderGroup(i) != got.disorderGroup(i))
      return fail("disorderGroup", i);
    if (expected.color(i) != got.color(i))
      return fail("color", i);
    if (expected.atomSelected(i) != got.atomSelected(i))
      return fail("selected", i);
    for (int axis = 0; axis < 3; ++axis) {
      if (expected.frozenAtomAxis(i, axis) != got.frozenAtomAxis(i, axis))
        return fail("frozen", i);
    }
    if (expected.layer(i) != got.layer(i))
      return fail("layer", i);
    if (expected.atomProperties().getDouble(kAtomKey, i) !=
        got.atomProperties().getDouble(kAtomKey, i))
      return fail("atom property", i);
    for (size_t f = 0; f < expected.coordinate3dCount(); ++f) {
      const auto& a = expected.coordinate3dRef(f);
      const auto& b = got.coordinate3dRef(f);
      const Vector3 va = i < a.size() ? a[i] : Vector3::Zero();
      const Vector3 vb = i < b.size() ? b[i] : Vector3::Zero();
      if (va != vb)
        return fail("coordinate set " + std::to_string(f), i);
    }
  }

  for (Index b = 0; b < expected.bondCount(); ++b) {
    if (sortedPair(expected.bondPair(b)) != sortedPair(got.bondPair(b)))
      return fail("bond pair", b);
    if (expected.bondOrder(b) != got.bondOrder(b))
      return fail("bond order", b);
    if (expected.bondLabel(b) != got.bondLabel(b))
      return fail("bond label", b);
    if (expected.bondProperties().getDouble(kBondKey, b) !=
        got.bondProperties().getDouble(kBondKey, b))
      return fail("bond property", b);
    const auto pair = expected.bondPair(b);
    if (got.bond(pair.first, pair.second).index() != b)
      return fail("bond lookup", b);
  }

  auto sameConstraints = [](const std::vector<Constraint>& a,
                            const std::vector<Constraint>& b) {
    if (a.size() != b.size())
      return false;
    for (size_t i = 0; i < a.size(); ++i) {
      if (a[i].aIndex() != b[i].aIndex() || a[i].bIndex() != b[i].bIndex() ||
          a[i].cIndex() != b[i].cIndex() || a[i].dIndex() != b[i].dIndex() ||
          a[i].value() != b[i].value())
        return false;
    }
    return true;
  };
  if (!sameConstraints(expected.constraints(), got.constraints()))
    return fail("constraints", 0);
  if (!sameConstraints(expected.scanCoordinates(), got.scanCoordinates()))
    return fail("scan coordinates", 0);

  if (expected.residueCount() != got.residueCount())
    return fail("residueCount", 0);
  for (Index r = 0; r < expected.residueCount(); ++r) {
    if (expected.residue(r).residueName() != got.residue(r).residueName() ||
        expected.residue(r).atomIndexMap() != got.residue(r).atomIndexMap())
      return fail("residue", r);
    if (expected.residueLabel(r) != got.residueLabel(r))
      return fail("residue label", r);
    if (expected.residueProperties().getDouble("snap-res", r) !=
        got.residueProperties().getDouble("snap-res", r))
      return fail("residue property", r);
  }
  return ::testing::AssertionSuccess();
}

void addResidue(Molecule& mol, const std::string& name, Index number,
                const std::vector<std::pair<std::string, Index>>& atoms)
{
  std::string residueName = name;
  char chain = 'A';
  Residue& residue = mol.addResidue(residueName, number, chain);
  for (const auto& entry : atoms)
    residue.addResidueAtom(entry.first, mol.atom(entry.second));
}

// Six atoms in a chain 0-1-2-3-4 with a branch 5 on atom 1, with something of
// every kind attached to each atom and bond.
Molecule makeMolecule()
{
  Molecule mol;
  for (unsigned char z : { 6, 6, 8, 7, 1, 16 })
    mol.addAtom(z, Vector3(z, 2.0 * z, 3.0));
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 2);
  mol.addBond(2, 3, 1);
  mol.addBond(3, 4, 3);
  mol.addBond(1, 5, 1);
  for (Index i = 0; i < 6; ++i) {
    mol.setAtomLabel(i, "L" + std::to_string(i));
    mol.setAtomPosition2d(i, Avogadro::Vector2(i, -double(i)));
    mol.setFormalCharge(i, static_cast<signed char>(i % 3) - 1);
    mol.setIsotope(i, static_cast<unsigned short>(10 + i));
    mol.setOccupancy(i, 0.1 * double(i + 1));
    mol.setDisorder(i, i % 2 == 0 ? "A" : "", std::to_string(i + 1));
    mol.setColor(i, Vector3ub(i, i + 1, i + 2));
    mol.setAtomSelected(i, i % 2 == 0);
    mol.atomProperties().setDouble(kAtomKey, i, 0.5 * double(i));
    mol.setLayer(i, i % 2);
  }
  mol.setFrozenAtomAxis(2, 1, true);
  mol.setFrozenAtomAxis(5, 0, true);
  for (Index b = 0; b < 5; ++b) {
    mol.setBondLabel(b, "B" + std::to_string(b));
    mol.bondProperties().setDouble(kBondKey, b, 10.0 + double(b));
  }

  // One full frame, one short one (it stops before atom 3), one empty.
  Array<Vector3> full;
  Array<Vector3> shortFrame;
  for (Index i = 0; i < 6; ++i) {
    full.push_back(Vector3(100.0 + i, 0.0, 0.0));
    if (i < 3)
      shortFrame.push_back(Vector3(200.0 + i, 0.0, 0.0));
  }
  mol.setCoordinate3d(full, 1);
  mol.setCoordinate3d(shortFrame, 2);
  mol.setCoordinate3d(0);
  return mol;
}

} // namespace

TEST(MoleculeSnapshotTest, defaultSnapshotsAreEmpty)
{
  EXPECT_TRUE(AtomSnapshot().isEmpty());
  EXPECT_TRUE(BondSnapshot().isEmpty());
  EXPECT_FALSE(AtomSnapshot().hasBonds());

  Molecule mol = makeMolecule();
  EXPECT_TRUE(mol.atomSnapshot(6).isEmpty());
  EXPECT_TRUE(mol.bondSnapshot(5).isEmpty());
  EXPECT_FALSE(mol.atomSnapshot(0).isEmpty());
  EXPECT_FALSE(mol.bondSnapshot(0).isEmpty());
}

TEST(MoleculeSnapshotTest, bondRoundTripInEveryPosition)
{
  for (Index id = 0; id < 5; ++id) {
    SCOPED_TRACE("bond " + std::to_string(id));
    Molecule mol = makeMolecule();
    const Molecule before = mol;
    const BondSnapshot snapshot = mol.bondSnapshot(id);
    ASSERT_TRUE(mol.removeBond(id));
    EXPECT_EQ(4u, mol.bondCount());
    ASSERT_TRUE(mol.restoreBondSnapshot(id, snapshot));
    EXPECT_TRUE(sameMolecule(before, mol));
  }
}

TEST(MoleculeSnapshotTest, bondRestoreRefusals)
{
  Molecule mol = makeMolecule();
  const BondSnapshot snapshot = mol.bondSnapshot(2);

  // The bond is still there: the count is not one less.
  const Molecule unchanged = mol;
  EXPECT_FALSE(mol.restoreBondSnapshot(2, snapshot));
  EXPECT_TRUE(sameMolecule(unchanged, mol));

  ASSERT_TRUE(mol.removeBond(2));
  const Molecule removed = mol;
  EXPECT_FALSE(mol.restoreBondSnapshot(2, BondSnapshot()));
  EXPECT_FALSE(mol.restoreBondSnapshot(5, snapshot)); // past bondCount()
  EXPECT_TRUE(sameMolecule(removed, mol));

  // Another bond removed as well: wrong count.
  ASSERT_TRUE(mol.removeBond(0));
  const Molecule twice = mol;
  EXPECT_FALSE(mol.restoreBondSnapshot(2, snapshot));
  EXPECT_TRUE(sameMolecule(twice, mol));
}

TEST(MoleculeSnapshotTest, bondRestoreRefusedWhenAlreadyBonded)
{
  Molecule mol = makeMolecule();
  const BondSnapshot snapshot = mol.bondSnapshot(2); // 2-3
  ASSERT_TRUE(mol.removeBond(2));
  mol.addBond(3, 2, 1); // the same atoms again, as a different bond
  ASSERT_TRUE(mol.removeBond(0));
  ASSERT_EQ(4u, mol.bondCount());
  const Molecule before = mol;
  EXPECT_FALSE(mol.restoreBondSnapshot(0, snapshot));
  EXPECT_TRUE(sameMolecule(before, mol));
}

TEST(MoleculeSnapshotTest, atomRoundTripWithEverything)
{
  // Atom 1 has three bonds, is named by a constraint and a scan coordinate
  // that go, and is in a residue that goes. Atom 5, the last, moves into its
  // place, and the constraint, scan coordinate and residue that name it must
  // follow it there and back.
  Molecule mol = makeMolecule();
  mol.addConstraint(1.5, 0, 1);
  mol.addConstraint(2.5, 2, 3);
  mol.addConstraint(90.0, 3, 5, 4);
  mol.addConstraint(60.0, 5, 3, 2, 4);
  mol.addConstraint(1.0, 5, 4);
  mol.addScanCoordinate(Constraint(1, 2));
  mol.addScanCoordinate(Constraint(0, 5));
  mol.addScanCoordinate(Constraint(3, 4));
  mol.addScanCoordinate(Constraint(5, 1, 0));
  addResidue(mol, "AAA", 1, { { "C0", 0 }, { "C1", 1 } });
  addResidue(mol, "BBB", 2, { { "O", 2 }, { "S", 5 } });
  addResidue(mol, "CCC", 3, { { "N", 3 }, { "H", 4 } });
  addResidue(mol, "DDD", 4, { { "CA", 1 }, { "CB", 3 } });
  mol.setResidueLabel(0, "first");
  mol.setResidueLabel(3, "fourth");
  mol.residueProperties().setDouble("snap-res", 0, 7.0);
  mol.residueProperties().setDouble("snap-res", 3, 9.0);
  mol.residueProperties().setDouble("snap-res", 1, 8.0);

  const Molecule before = mol;
  const AtomSnapshot snapshot = mol.atomSnapshot(1);
  EXPECT_TRUE(snapshot.hasBonds());
  ASSERT_TRUE(mol.removeAtom(1));

  // What the removal did, so that the test is not a round trip of nothing.
  EXPECT_EQ(5u, mol.atomCount());
  EXPECT_EQ(2u, mol.residueCount());
  EXPECT_EQ(16, mol.atomicNumber(1)); // atom 5 moved into the hole
  EXPECT_EQ(4u, mol.constraints().size());
  EXPECT_EQ(2u, mol.scanCoordinates().size());

  ASSERT_TRUE(mol.restoreAtomSnapshot(1, snapshot));
  EXPECT_TRUE(sameMolecule(before, mol));

  // And it can be taken out and put back again.
  const AtomSnapshot again = mol.atomSnapshot(1);
  ASSERT_TRUE(mol.removeAtom(1));
  ASSERT_TRUE(mol.restoreAtomSnapshot(1, again));
  EXPECT_TRUE(sameMolecule(before, mol));
}

TEST(MoleculeSnapshotTest, atomRoundTripInEveryPosition)
{
  for (Index id = 0; id < 6; ++id) {
    SCOPED_TRACE("atom " + std::to_string(id));
    Molecule mol = makeMolecule();
    mol.addConstraint(1.5, 0, id == 0 ? 1 : id);
    mol.addConstraint(1.0, 5, 4);
    mol.addScanCoordinate(Constraint(id, (id + 1) % 6));
    addResidue(mol, "AAA", 1, { { "X", id }, { "Y", (id + 1) % 6 } });
    addResidue(mol, "BBB", 2, { { "Z", 5 } });
    const Molecule before = mol;
    const AtomSnapshot snapshot = mol.atomSnapshot(id);
    ASSERT_TRUE(mol.removeAtom(id));
    ASSERT_TRUE(mol.restoreAtomSnapshot(id, snapshot));
    EXPECT_TRUE(sameMolecule(before, mol));
  }
}

TEST(MoleculeSnapshotTest, atomInTwoResidues)
{
  Molecule mol = makeMolecule();
  addResidue(mol, "AAA", 1, { { "X", 2 } });
  addResidue(mol, "BBB", 2, { { "Y", 4 } });
  addResidue(mol, "CCC", 3, { { "Z", 2 }, { "W", 5 } });
  mol.setResidueLabel(2, "third");
  mol.residueProperties().setDouble("snap-res", 0, 1.0);
  mol.residueProperties().setDouble("snap-res", 1, 2.0);
  mol.residueProperties().setDouble("snap-res", 2, 3.0);
  const Molecule before = mol;
  const AtomSnapshot snapshot = mol.atomSnapshot(2);
  ASSERT_TRUE(mol.removeAtom(2));
  EXPECT_EQ(1u, mol.residueCount());
  ASSERT_TRUE(mol.restoreAtomSnapshot(2, snapshot));
  EXPECT_TRUE(sameMolecule(before, mol));
}

TEST(MoleculeSnapshotTest, atomWithoutBondsOrFrames)
{
  Molecule mol;
  mol.addAtom(8);
  mol.addAtom(6);
  mol.addAtom(1);
  mol.setAtomLabel(0, "O");
  const Molecule before = mol;
  for (Index id : { 0u, 1u, 2u }) {
    const AtomSnapshot snapshot = mol.atomSnapshot(id);
    EXPECT_FALSE(snapshot.hasBonds());
    ASSERT_TRUE(mol.removeAtom(id));
    ASSERT_TRUE(mol.restoreAtomSnapshot(id, snapshot));
    EXPECT_TRUE(sameMolecule(before, mol));
  }
}

TEST(MoleculeSnapshotTest, onlyAtom)
{
  Molecule mol;
  mol.addAtom(8, Vector3(1, 2, 3));
  mol.setAtomLabel(0, "only");
  mol.setCoordinate3d(Array<Vector3>(1, Vector3(4, 5, 6)), 1);
  const Molecule before = mol;
  const AtomSnapshot snapshot = mol.atomSnapshot(0);
  ASSERT_TRUE(mol.removeAtom(0));
  EXPECT_EQ(0u, mol.atomCount());
  ASSERT_TRUE(mol.restoreAtomSnapshot(0, snapshot));
  EXPECT_TRUE(sameMolecule(before, mol));
}

TEST(MoleculeSnapshotTest, elementMaskAndCustomElement)
{
  Molecule mol;
  mol.addAtom(6);
  mol.addAtom(Avogadro::CustomElementMin);
  mol.addAtom(7);
  const Molecule before = mol;
  for (Index id : { 1u, 2u }) {
    const AtomSnapshot snapshot = mol.atomSnapshot(id);
    ASSERT_TRUE(mol.removeAtom(id));
    EXPECT_NE(before.elements(), mol.elements());
    ASSERT_TRUE(mol.restoreAtomSnapshot(id, snapshot));
    EXPECT_TRUE(sameMolecule(before, mol));
  }
}

TEST(MoleculeSnapshotTest, framesOfDifferentLengths)
{
  // Five atoms and five frames: full, short (reaches atom 2), shorter (does
  // not reach it), longer than the atom count, and empty.
  Molecule mol;
  for (int i = 0; i < 5; ++i)
    mol.addAtom(6, Vector3(i, 0, 0));
  const size_t lengths[] = { 5, 3, 1, 7, 0 };
  for (size_t f = 0; f < 5; ++f) {
    Array<Vector3> frame;
    for (size_t i = 0; i < lengths[f]; ++i)
      frame.push_back(Vector3(double(f * 10 + i), 1.0, 1.0));
    mol.setCoordinate3d(frame, f + 1);
  }
  for (Index id = 0; id < 5; ++id) {
    SCOPED_TRACE("atom " + std::to_string(id));
    const Molecule before = mol;
    const AtomSnapshot snapshot = mol.atomSnapshot(id);
    ASSERT_TRUE(mol.removeAtom(id));
    ASSERT_TRUE(mol.restoreAtomSnapshot(id, snapshot));
    ASSERT_TRUE(sameMolecule(before, mol));
    // The lengths themselves, which sameMolecule() reads past.
    for (size_t f = 0; f < 5; ++f)
      EXPECT_EQ(before.coordinate3dRef(f + 1).size(),
                mol.coordinate3dRef(f + 1).size());
  }
}

TEST(MoleculeSnapshotTest, shortOptionalArrays)
{
  // Optional arrays that stop before the atom: atoms added after the label and
  // the property were set.
  Molecule mol;
  mol.addAtom(6);
  mol.addAtom(6);
  mol.setAtomLabel(0, "zero");
  mol.setIsotope(1, 13);
  mol.atomProperties().setDouble(kAtomKey, 0, 1.0);
  mol.addAtom(7);
  mol.addAtom(8);
  for (Index id = 0; id < 4; ++id) {
    SCOPED_TRACE("atom " + std::to_string(id));
    const Molecule before = mol;
    const AtomSnapshot snapshot = mol.atomSnapshot(id);
    ASSERT_TRUE(mol.removeAtom(id));
    ASSERT_TRUE(mol.restoreAtomSnapshot(id, snapshot));
    EXPECT_TRUE(sameMolecule(before, mol));
    EXPECT_EQ(before.atomLabels().size(), mol.atomLabels().size());
  }
}

TEST(MoleculeSnapshotTest, atomRestoreRefusals)
{
  Molecule mol = makeMolecule();
  const AtomSnapshot snapshot = mol.atomSnapshot(2);

  // Not removed yet.
  Molecule unchanged = mol;
  EXPECT_FALSE(mol.restoreAtomSnapshot(2, snapshot));
  EXPECT_TRUE(sameMolecule(unchanged, mol));

  ASSERT_TRUE(mol.removeAtom(2));
  unchanged = mol;
  EXPECT_FALSE(mol.restoreAtomSnapshot(2, AtomSnapshot()));
  EXPECT_FALSE(mol.restoreAtomSnapshot(6, snapshot));
  EXPECT_FALSE(mol.restoreAtomSnapshot(MaxIndex, snapshot));
  // In range, and the count matches, but not the index it was taken at.
  EXPECT_FALSE(mol.restoreAtomSnapshot(0, snapshot));
  EXPECT_FALSE(mol.restoreAtomSnapshot(1, snapshot));
  EXPECT_TRUE(sameMolecule(unchanged, mol));

  // Still restores at its own index.
  EXPECT_TRUE(mol.restoreAtomSnapshot(2, snapshot));
  ASSERT_TRUE(mol.removeAtom(2));
  unchanged = mol;

  // A second removal: the count is two less.
  ASSERT_TRUE(mol.removeAtom(0));
  unchanged = mol;
  EXPECT_FALSE(mol.restoreAtomSnapshot(2, snapshot));
  EXPECT_TRUE(sameMolecule(unchanged, mol));
}

TEST(MoleculeSnapshotTest, firstAtomWithItsBond)
{
  Molecule mol;
  mol.addAtom(6);
  mol.addAtom(8);
  mol.addAtom(1);
  mol.addBond(0, 1, 2);
  const Molecule before = mol;

  const AtomSnapshot snapshot = mol.atomSnapshot(0);
  ASSERT_TRUE(mol.removeAtom(0));
  EXPECT_EQ(mol.bondCount(), static_cast<Index>(0));

  const Molecule removed = mol;
  EXPECT_FALSE(mol.restoreAtomSnapshot(1, snapshot));
  EXPECT_TRUE(sameMolecule(removed, mol));

  ASSERT_TRUE(mol.restoreAtomSnapshot(0, snapshot));
  ASSERT_EQ(mol.bondCount(), static_cast<Index>(1));
  EXPECT_EQ(mol.bondOrder(0), 2);
  EXPECT_TRUE(sameMolecule(before, mol));
}

TEST(MoleculeSnapshotTest, bondsOfAnAtomRestoreWithTheirOwnState)
{
  // A star: atom 0 bonded to the others, so that every removal of one of its
  // bonds moves another into the hole, and a few bonds elsewhere so that the
  // last bond is not always the atom's.
  Molecule mol;
  for (int i = 0; i < 7; ++i)
    mol.addAtom(6);
  mol.addBond(1, 2, 1);
  for (Index i = 1; i < 5; ++i)
    mol.addBond(0, i, static_cast<unsigned char>(i));
  mol.addBond(5, 6, 2);
  mol.addBond(3, 6, 1);
  mol.addBond(0, 6, 3);
  mol.addBond(2, 5, 1);
  for (Index b = 0; b < mol.bondCount(); ++b) {
    // Labels and properties on some bonds only, so that the columns are short.
    if (b % 3 != 1)
      mol.setBondLabel(b, "b" + std::to_string(b));
    if (b < 6)
      mol.bondProperties().setDouble(kBondKey, b, double(b));
  }
  for (Index id = 0; id < 7; ++id) {
    SCOPED_TRACE("atom " + std::to_string(id));
    const Molecule before = mol;
    const AtomSnapshot snapshot = mol.atomSnapshot(id);
    ASSERT_TRUE(mol.removeAtom(id));
    ASSERT_TRUE(mol.restoreAtomSnapshot(id, snapshot));
    EXPECT_TRUE(sameMolecule(before, mol));
  }
}

TEST(MoleculeSnapshotTest, connectivityAfterRestore)
{
  // 0-1 and 2-3-4: remove 0 (the last atom, 4, moves to 0), restore.
  Molecule mol;
  for (int i = 0; i < 5; ++i)
    mol.addAtom(6);
  mol.addBond(0, 1, 1);
  mol.addBond(2, 3, 1);
  mol.addBond(3, 4, 1);
  const AtomSnapshot snapshot = mol.atomSnapshot(0);
  ASSERT_TRUE(mol.removeAtom(0));
  ASSERT_TRUE(mol.restoreAtomSnapshot(0, snapshot));
  const auto components = mol.graph().connectedComponents();
  ASSERT_EQ(2u, components.size());
  EXPECT_EQ(1u, mol.graph().connectedComponent(0).count(1));
  EXPECT_EQ(0u, mol.graph().connectedComponent(0).count(2));
  EXPECT_EQ(3u, mol.graph().connectedComponent(4).size());
}

TEST(MoleculeSnapshotTest, calculatedResultsAreNotRestored)
{
  Molecule mol = makeMolecule();
  mol.setPartialCharges("test", Eigen::MatrixXd::Ones(6, 1));
  mol.setForceVector(2, Vector3(1, 2, 3));
  const AtomSnapshot snapshot = mol.atomSnapshot(2);
  ASSERT_TRUE(mol.removeAtom(2));
  ASSERT_TRUE(mol.restoreAtomSnapshot(2, snapshot));
  EXPECT_TRUE(mol.partialChargeTypes().empty());
  EXPECT_TRUE(mol.forceVectors().empty());
}

// A color that was grown by a setter (and then undone) holds the element's
// color of whichever atom was at that index. When the removed atom comes back
// the entry at its index must be its own element's.
TEST(MoleculeSnapshotTest, colorColumnGrownAfterTheRemoval)
{
  Molecule mol;
  mol.addAtom(6);
  mol.addAtom(9);
  const Molecule before = mol;
  const AtomSnapshot snapshot = mol.atomSnapshot(0);
  ASSERT_TRUE(mol.removeAtom(0)); // the fluorine is atom 0 now
  // What setting and un-setting a color leaves: an entry with the element's
  // color for every atom.
  mol.setColor(0, Vector3ub(mol.color(0)));
  ASSERT_EQ(1u, mol.colors().size());
  ASSERT_TRUE(mol.restoreAtomSnapshot(0, snapshot));
  EXPECT_TRUE(sameMolecule(before, mol));
  EXPECT_EQ(Vector3ub(Avogadro::Core::Elements::color(6)), mol.color(0));
  EXPECT_EQ(Vector3ub(Avogadro::Core::Elements::color(9)), mol.color(1));
}
