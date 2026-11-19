/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "aligntool.h"

#include <gtest/gtest.h>

#include <QtTest/QSignalSpy>

#include <functional>
#include <vector>

using Avogadro::Index;
using Avogadro::Vector3;
using Avogadro::QtPlugins::AlignTool;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::expectNear;
using Avogadro::QtPluginsTests::MoleculeSnapshot;
using Avogadro::QtPluginsTests::NoMoleculeMessage;
using Avogadro::QtPluginsTests::recordKnownDeviation;
using Avogadro::QtPluginsTests::recordUndecided;

// Golden values are for CommandTestHarness::buildPeroxideChain():
//   H0 (0, 1, 0), O1 (0, 0, 0), O2 (1.5, 0, 0), H3 (1.5, 0, 1)
namespace {

// centerAtom subtracts a position whose components are exactly
// representable, so it is exact; alignAtom goes through a quaternion, so
// allow a few roundings.
constexpr double RotTol = 1e-9;

class AlignToolCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildPeroxideChain();
    m_harness.attach(&m_tool);
    m_harness.registerCommands();
  }

  Vector3 position(Index i) const
  {
    return m_harness.molecule()->atomPosition3d(i);
  }

  // Run a mutating command, check it is one clean undo step that changed
  // only coordinates, and that undo/redo restore each state exactly.
  void expectOneUndoableMove(const char* command, const QVariantMap& options,
                             const std::function<void()>& checkMoved)
  {
    const MoleculeSnapshot before = m_harness.snapshot();
    const CommandOutcome out = m_harness.run(command, options);
    EXPECT_TRUE(out.claimed) << command;
    EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
    EXPECT_TRUE(out.clean()) << describe(out);
    checkMoved();

    const MoleculeSnapshot moved = m_harness.snapshot();
    EXPECT_EQ(before.differences(moved, false), QStringList({ "coordinates" }));
    EXPECT_EQ(moved.undoCount, before.undoCount + 1);

    EXPECT_TRUE(m_harness.undo().isEmpty());
    EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());
    EXPECT_TRUE(m_harness.redo().isEmpty());
    EXPECT_EQ(m_harness.snapshot().differences(moved), QStringList());
  }

  AlignTool m_tool;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(AlignToolCommandTest, registersDocumentedCommands)
{
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  EXPECT_EQ(registered.keys(),
            QStringList({ "alignAtom", "alignPickedAtoms", "centerAtom" }));
}

// Translate everything by -O2 = (-1.5, 0, 0).
TEST_F(AlignToolCommandTest, centerAtomUndoRedo)
{
  expectOneUndoableMove("centerAtom", { { "id", qlonglong(2) } }, [this]() {
    EXPECT_EQ(position(0), Vector3(-1.5, 1.0, 0.0));
    EXPECT_EQ(position(1), Vector3(-1.5, 0.0, 0.0));
    EXPECT_EQ(position(2), Vector3(0.0, 0.0, 0.0));
    EXPECT_EQ(position(3), Vector3(0.0, 0.0, 1.0));
  });
}

// "index" is accepted as an alias for "id".
TEST_F(AlignToolCommandTest, centerAtomAcceptsIndexKey)
{
  expectOneUndoableMove("centerAtom", { { "index", qlonglong(3) } }, [this]() {
    EXPECT_EQ(position(0), Vector3(-1.5, 1.0, -1.0));
    EXPECT_EQ(position(3), Vector3(0.0, 0.0, 0.0));
  });
}

// Rotating H0's direction (0, 1, 0) onto +x is -90 degrees about +z:
// (x, y, z) -> (y, -x, z). The atoms rotate about the origin, where O1 is.
TEST_F(AlignToolCommandTest, alignAtomToXUndoRedo)
{
  expectOneUndoableMove(
    "alignAtom", { { "id", qlonglong(0) }, { "axis", "x" } }, [this]() {
      expectNear(position(0), Vector3(1.0, 0.0, 0.0), RotTol, "H0");
      expectNear(position(1), Vector3(0.0, 0.0, 0.0), RotTol, "O1");
      expectNear(position(2), Vector3(0.0, -1.5, 0.0), RotTol, "O2");
      expectNear(position(3), Vector3(0.0, -1.5, 1.0), RotTol, "H3");
    });
}

TEST_F(AlignToolCommandTest, alignAtomToNumericAxisIsRejected)
{
  const CommandOutcome out = m_harness.run(
    "alignAtom", { { "id", qlonglong(2) }, { "axis", qlonglong(1) } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed);
  EXPECT_EQ(out.failedCount, 1);
}

// Contract: unknown -> false.
TEST_F(AlignToolCommandTest, unknownCommandIsNotClaimed)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  for (const char* name : { "notACommand", "CenterAtom", "selectAll" }) {
    const CommandOutcome out = m_harness.run(name);
    EXPECT_FALSE(out.claimed) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Missing or invalid options are claimed and fail via commandFailed().
TEST_F(AlignToolCommandTest, missingOrInvalidOptionsFail)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  const std::vector<std::pair<const char*, QVariantMap>> cases = {
    { "centerAtom", {} },
    { "alignAtom", { { "axis", "x" } } },
    { "alignAtom", { { "id", qlonglong(0) } } },
    { "alignAtom", { { "id", qlonglong(0) }, { "axis", "w" } } },
    { "alignAtom", { { "id", qlonglong(0) }, { "axis", "X" } } },
    { "alignAtom", { { "id", qlonglong(0) }, { "axis", qlonglong(3) } } },
    { "alignAtom", { { "id", qlonglong(0) }, { "axis", qlonglong(-1) } } },
    { "alignPickedAtoms", {} },
    { "alignPickedAtoms", { { "axis", "invalid" } } },
  };
  for (const auto& [name, options] : cases) {
    const CommandOutcome out = m_harness.run(name, options);
    EXPECT_TRUE(out.claimed) << name;
    EXPECT_EQ(out.status, CommandStatus::Failed) << name;
    EXPECT_EQ(out.failedCount, 1) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Out-of-range or negative IDs are invalid and fail.
TEST_F(AlignToolCommandTest, outOfRangeIdFails)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  const std::vector<std::pair<const char*, QVariantMap>> cases = {
    { "centerAtom", { { "id", qlonglong(4) } } }, // == atomCount
    { "centerAtom", { { "id", qlonglong(-1) } } },
    { "centerAtom", { { "index", qlonglong(99) } } },
    { "alignAtom", { { "id", qlonglong(4) }, { "axis", "x" } } },
    { "alignAtom", { { "id", qlonglong(-1) }, { "axis", "z" } } },
  };
  for (const auto& [name, options] : cases) {
    const CommandOutcome out = m_harness.run(name, options);
    EXPECT_TRUE(out.claimed) << name;
    EXPECT_EQ(out.status, CommandStatus::Failed) << name;
    EXPECT_EQ(out.failedCount, 1) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Non-numeric ID fails validation.
TEST_F(AlignToolCommandTest, nonNumericIdFails)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  const CommandOutcome out = m_harness.run("centerAtom", { { "id", "abc" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_EQ(out.failedCount, 1);
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Contract (decision 2): a command that changes nothing must not push an
// undo entry. Centering the atom already at the origin, or aligning an atom
// already on the axis, rewrites identical coordinates as a new undo step.
TEST_F(AlignToolCommandTest, knownDeviationNoOpMovePushesUndoEntry)
{
  recordKnownDeviation("centerAtom/alignAtom that move nothing push an undo "
                       "entry");

  const std::vector<std::pair<const char*, QVariantMap>> cases = {
    { "centerAtom", { { "id", qlonglong(1) } } },                 // O1 at 0
    { "alignAtom", { { "id", qlonglong(2) }, { "axis", "x" } } }, // O2 on x
  };
  for (const auto& [name, options] : cases) {
    const MoleculeSnapshot before = m_harness.snapshot();
    const CommandOutcome out = m_harness.run(name, options);
    EXPECT_EQ(out.status, CommandStatus::Finished) << name;
    const MoleculeSnapshot after = m_harness.snapshot();
    EXPECT_EQ(before.differences(after, false), QStringList()) << name;
    // When these fail, expect out.clean() and after == before.
    EXPECT_EQ(after.undoCount, before.undoCount + 1) << name;
    EXPECT_FALSE(out.clean()) << name;
  }
}

// Contract (decision 1): no molecule -> true + commandFailed("No molecule").
// Holds for a tool that never had a molecule and for one detached with
// setMolecule(nullptr).
TEST_F(AlignToolCommandTest, noMoleculeFails)
{
  AlignTool fresh;
  QSignalSpy failed(&fresh, &AlignTool::commandFailed);
  EXPECT_TRUE(fresh.handleCommand("centerAtom", { { "id", qlonglong(0) } }));
  ASSERT_EQ(failed.count(), 1);
  EXPECT_EQ(failed.at(0).at(0).toString(), QString(NoMoleculeMessage));
  EXPECT_FALSE(fresh.handleCommand("notACommand", {}));
  EXPECT_EQ(failed.count(), 1);

  const MoleculeSnapshot before = m_harness.snapshot();
  m_harness.setPluginMolecule(nullptr);
  const CommandOutcome out =
    m_harness.run("centerAtom", { { "id", qlonglong(2) } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_EQ(out.message, QString(NoMoleculeMessage));
  EXPECT_EQ(m_harness.snapshot(), before);
}

// setMolecule(nullptr) must detach the tool from the old molecule, which may
// be deleted next. Re-attaching must make it work again.
TEST_F(AlignToolCommandTest, setMoleculeNullDetachesTool)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  m_harness.setPluginMolecule(nullptr);

  const CommandOutcome center =
    m_harness.run("centerAtom", { { "id", qlonglong(2) } });
  EXPECT_TRUE(center.clean()) << describe(center);
  const CommandOutcome align =
    m_harness.run("alignAtom", { { "id", qlonglong(0) }, { "axis", "x" } });
  EXPECT_TRUE(align.clean()) << describe(align);
  EXPECT_EQ(m_harness.snapshot(), before);

  m_harness.setPluginMolecule(m_harness.molecule());
  const CommandOutcome again =
    m_harness.run("centerAtom", { { "id", qlonglong(2) } });
  EXPECT_TRUE(again.claimed);
  EXPECT_TRUE(again.clean()) << describe(again);
  EXPECT_EQ(position(2), Vector3(0.0, 0.0, 0.0));
}

// Aligning an atom that sits at the origin has no direction to rotate,
// and AlignTool fails with a descriptive error.
TEST_F(AlignToolCommandTest, alignAtomAtOriginFails)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  const CommandOutcome out =
    m_harness.run("alignAtom", { { "id", qlonglong(1) }, { "axis", "x" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_EQ(out.failedCount, 1);
  EXPECT_EQ(out.message,
            "Atom 1 is at the origin and cannot define an alignment axis.");
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Aligning picked atoms when none have been picked fails with a descriptive
// error.
TEST_F(AlignToolCommandTest, alignPickedAtomsWithNoPickedAtomsFails)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  const CommandOutcome out =
    m_harness.run("alignPickedAtoms", { { "axis", "z" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_EQ(out.failedCount, 1);
  EXPECT_EQ(
    out.message,
    "No atoms have been picked for alignment. Pick 1 or 2 atoms first.");
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(m_harness.snapshot(), before);
}
