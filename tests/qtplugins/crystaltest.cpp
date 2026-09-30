/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "crystal.h"

#include <avogadro/core/unitcell.h>

#include <gtest/gtest.h>

using Avogadro::Index;
using Avogadro::Matrix3;
using Avogadro::Vector3;
using Avogadro::Core::UnitCell;
using Avogadro::QtPlugins::Crystal;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::expectNear;
using Avogadro::QtPluginsTests::MoleculeSnapshot;
using Avogadro::QtPluginsTests::recordKnownDeviation;
using Avogadro::QtPluginsTests::recordUndecided;

namespace {

// Every coordinate and cell entry below is a small multiple of a power of
// two, so the fractional conversions are exact in binary; the tolerance only
// allows for the matrix inverse.
constexpr double Tol = 1e-12;

class CrystalCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildEmpty();
    m_harness.attach(&m_crystal);
    m_harness.registerCommands();
  }

  // Cubic cell, a = b = c = 4 A, three argon atoms. Ar-Ar pairs are at least
  // 2.83 A apart after wrapping, beyond the Ar-Ar bonding cutoff (Pyykko
  // r_cov 0.96 A each, + 0.45 A tolerance = 2.37 A), so wrapping perceives
  // no bonds.
  //   Ar0 ( 5, -1, 2): fractional (1.25, -0.25, 0.5) -> (0.25, 0.75, 0.5)
  //                    -> (1, 3, 2)
  //   Ar1 ( 3,  1, 2): already inside, unchanged
  //   Ar2 ( 4,  0, 0): fractional (1, 0, 0), on the far face -> (0, 0, 0)
  void buildCubicArgon()
  {
    m_harness.buildEmpty();
    auto* mol = m_harness.molecule();
    mol->setUnitCell(new UnitCell(
      Vector3(4.0, 0.0, 0.0), Vector3(0.0, 4.0, 0.0), Vector3(0.0, 0.0, 4.0)));
    mol->addAtom(18, Vector3(5.0, -1.0, 2.0));
    mol->addAtom(18, Vector3(3.0, 1.0, 2.0));
    mol->addAtom(18, Vector3(4.0, 0.0, 0.0));
  }

  Vector3 position(Index i) const
  {
    return m_harness.molecule()->atomPosition3d(i);
  }

  Crystal m_crystal;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(CrystalCommandTest, registersDocumentedCommands)
{
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  EXPECT_EQ(registered.keys(),
            QStringList({ "standardCrystalOrientation", "wrapUnitCell" }));
}

TEST_F(CrystalCommandTest, wrapUnitCellUndoRedo)
{
  buildCubicArgon();
  const MoleculeSnapshot before = m_harness.snapshot();

  const CommandOutcome out = m_harness.run("wrapUnitCell");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  expectNear(position(0), Vector3(1.0, 3.0, 2.0), Tol, "Ar0");
  expectNear(position(1), Vector3(3.0, 1.0, 2.0), Tol, "Ar1");
  expectNear(position(2), Vector3(0.0, 0.0, 0.0), Tol, "Ar2");

  const MoleculeSnapshot wrapped = m_harness.snapshot();
  EXPECT_EQ(before.differences(wrapped, false), QStringList({ "coordinates" }));
  EXPECT_EQ(wrapped.undoCount, before.undoCount + 1);

  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());
  EXPECT_TRUE(m_harness.redo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(wrapped), QStringList());
}

// Cell a = (0, 3, 0), b = (-4, 0, 0), c = (0, 0, 5): right-handed
// (a x b = (0, 0, 12), c . (a x b) = 60 > 0), but a is not along x.
// Standard orientation puts a on +x and b in the xy plane: a' = (3, 0, 0),
// b' = (0, 4, 0), c' = (0, 0, det / (|a| b'_y) = 60 / 12 = 5). Atoms keep
// their fractional coordinates: (0, 1.5, 2.5) = 0.5 a + 0.5 c
// -> 0.5 a' + 0.5 c' = (1.5, 0, 2.5).
TEST_F(CrystalCommandTest, standardCrystalOrientationUndoRedo)
{
  auto* mol = m_harness.molecule();
  mol->setUnitCell(new UnitCell(Vector3(0.0, 3.0, 0.0), Vector3(-4.0, 0.0, 0.0),
                                Vector3(0.0, 0.0, 5.0)));
  mol->addAtom(18, Vector3(0.0, 1.5, 2.5));
  const MoleculeSnapshot before = m_harness.snapshot();

  const CommandOutcome out = m_harness.run("standardCrystalOrientation");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);

  Matrix3 expected = Matrix3::Zero();
  expected.diagonal() << 3.0, 4.0, 5.0;
  const Matrix3 cell = m_harness.molecule()->unitCell()->cellMatrix();
  EXPECT_TRUE((cell - expected).cwiseAbs().maxCoeff() <= Tol) << cell;
  expectNear(position(0), Vector3(1.5, 0.0, 2.5), Tol, "Ar0");

  const MoleculeSnapshot oriented = m_harness.snapshot();
  EXPECT_EQ(before.differences(oriented, false),
            QStringList({ "coordinates", "unit cell" }));
  EXPECT_EQ(oriented.undoCount, before.undoCount + 1);

  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());
  EXPECT_TRUE(m_harness.redo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(oriented), QStringList());
}

TEST_F(CrystalCommandTest, unknownCommandIsNotClaimed)
{
  buildCubicArgon();
  const MoleculeSnapshot before = m_harness.snapshot();
  for (const char* name : { "notACommand", "WrapUnitCell", "buildSupercell" }) {
    const CommandOutcome out = m_harness.run(name);
    EXPECT_FALSE(out.claimed) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Release plan section 4.2: wrapUnitCell -> wrapUnitCell. The second wrap
// moves nothing, but RWMolecule::wrapAtomsToCell() pushes its positions
// command unconditionally (decision 2: it must not). The same holds for
// orienting a cell that is already standard.
TEST_F(CrystalCommandTest, knownDeviationNoOpCrystalEditPushesUndoEntry)
{
  recordKnownDeviation("a second wrapUnitCell, or standardCrystalOrientation "
                       "on a standard cell, pushes an undo entry");

  buildCubicArgon();
  ASSERT_EQ(m_harness.run("wrapUnitCell").status, CommandStatus::Finished);

  for (const char* name : { "wrapUnitCell", "standardCrystalOrientation" }) {
    const MoleculeSnapshot before = m_harness.snapshot();
    const CommandOutcome out = m_harness.run(name);
    EXPECT_EQ(out.status, CommandStatus::Finished) << name;
    const MoleculeSnapshot after = m_harness.snapshot();
    EXPECT_EQ(before.differences(after, false), QStringList()) << name;
    // When these fail, expect out.clean() and after == before.
    EXPECT_EQ(after.undoCount, before.undoCount + 1) << name;
    EXPECT_FALSE(out.clean()) << name;
  }
}

// Every mutating command must be undoable. wrapAtomsToCell() clears and
// re-perceives bonds on the molecule directly, but its undo command only
// stores positions, so undo restores the coordinates and not the bonds.
TEST_F(CrystalCommandTest, knownDeviationWrapUndoDoesNotRestoreBonds)
{
  recordKnownDeviation("undoing wrapUnitCell does not restore the bonds the "
                       "wrap removed");

  buildCubicArgon();
  // A bond perception would never make (Ar0-Ar1 is 2.83 A before the wrap,
  // beyond the 0.96 + 0.96 + 0.45 = 2.37 A cutoff), so it only survives if
  // undo restores it.
  m_harness.molecule()->addBond(0, 1, 1);
  const MoleculeSnapshot before = m_harness.snapshot();

  ASSERT_EQ(m_harness.run("wrapUnitCell").status, CommandStatus::Finished);
  EXPECT_TRUE(m_harness.snapshot().bondPairs.empty());

  EXPECT_TRUE(m_harness.undo().isEmpty());
  const MoleculeSnapshot undone = m_harness.snapshot();
  EXPECT_EQ(undone.positions, before.positions);
  // When this fails, expect undone.differences(before, false) to be empty.
  EXPECT_EQ(undone.differences(before, false), QStringList({ "bonds" }));
}

// Contract (decision 1): no molecule -> true + commandFailed("No molecule").
TEST_F(CrystalCommandTest, knownDeviationNoMoleculeIsNotClaimed)
{
  recordKnownDeviation("with no molecule every command returns false");

  m_harness.setPluginMolecule(nullptr);
  for (const char* name : { "wrapUnitCell", "standardCrystalOrientation" }) {
    const CommandOutcome out = m_harness.run(name);
    // When this fails, expect claimed, Failed, NoMoleculeMessage.
    EXPECT_FALSE(out.claimed) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
}

// Not settled by the decisions: without a unit cell both commands claim the
// command and silently do nothing (no undo entry either).
TEST_F(CrystalCommandTest, undecidedNoUnitCellIsSilentNoOp)
{
  recordUndecided("wrapUnitCell/standardCrystalOrientation without a unit "
                  "cell return true and do nothing");

  m_harness.molecule()->addAtom(18, Vector3(5.0, -1.0, 2.0));
  const MoleculeSnapshot before = m_harness.snapshot();
  for (const char* name : { "wrapUnitCell", "standardCrystalOrientation" }) {
    const CommandOutcome out = m_harness.run(name);
    EXPECT_TRUE(out.claimed) << name;
    EXPECT_EQ(out.status, CommandStatus::Finished) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}
