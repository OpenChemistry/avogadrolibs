/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "aligntool.h"

#include <gtest/gtest.h>

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
  EXPECT_EQ(registered.keys(), QStringList({ "alignAtom", "centerAtom" }));
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

// A numeric axis (JSON numbers arrive as qlonglong): 1 is y. Rotating O2's
// direction (1, 0, 0) onto +y is +90 degrees about +z: (x, y, z) -> (-y, x, z).
TEST_F(AlignToolCommandTest, alignAtomToNumericAxis)
{
  expectOneUndoableMove(
    "alignAtom", { { "id", qlonglong(2) }, { "axis", qlonglong(1) } },
    [this]() {
      expectNear(position(0), Vector3(-1.0, 0.0, 0.0), RotTol, "H0");
      expectNear(position(2), Vector3(0.0, 1.5, 0.0), RotTol, "O2");
      expectNear(position(3), Vector3(0.0, 1.5, 1.0), RotTol, "H3");
    });
}

// Contract: unknown -> false. AlignTool claims anything it does not
// recognize ("return true; // nothing to handle").
TEST_F(AlignToolCommandTest, knownDeviationUnknownCommandIsClaimed)
{
  recordKnownDeviation("unknown commands return true");

  const MoleculeSnapshot before = m_harness.snapshot();
  for (const char* name : { "notACommand", "CenterAtom", "selectAll" }) {
    const CommandOutcome out = m_harness.run(name);
    // When this fails, expect claimed == false.
    EXPECT_TRUE(out.claimed) << name;
    EXPECT_EQ(out.status, CommandStatus::Finished) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Contract (decision 4): missing/invalid options -> true + commandFailed().
// AlignTool returns false with no signal.
TEST_F(AlignToolCommandTest, knownDeviationMissingOptionsAreNotClaimed)
{
  recordKnownDeviation("missing id, or missing/unknown axis, returns false");

  const MoleculeSnapshot before = m_harness.snapshot();
  const std::vector<std::pair<const char*, QVariantMap>> cases = {
    { "centerAtom", {} },
    { "alignAtom", { { "axis", "x" } } },
    { "alignAtom", { { "id", qlonglong(0) } } },
    { "alignAtom", { { "id", qlonglong(0) }, { "axis", "w" } } },
    { "alignAtom", { { "id", qlonglong(0) }, { "axis", "X" } } },
    { "alignAtom", { { "id", qlonglong(0) }, { "axis", qlonglong(3) } } },
    { "alignAtom", { { "id", qlonglong(0) }, { "axis", qlonglong(-1) } } },
  };
  for (const auto& [name, options] : cases) {
    const CommandOutcome out = m_harness.run(name, options);
    // When these fail, expect claimed and status == Failed.
    EXPECT_FALSE(out.claimed) << name;
    EXPECT_EQ(out.failedCount, 0) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Contract (decision 4): out-of-range ids are invalid options. AlignTool
// claims them and silently does nothing.
TEST_F(AlignToolCommandTest, knownDeviationOutOfRangeIdIsSilentNoOp)
{
  recordKnownDeviation("out-of-range or negative id returns true and does "
                       "nothing, with no commandFailed()");

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
    // When this fails, expect status == Failed.
    EXPECT_EQ(out.status, CommandStatus::Finished) << name;
    EXPECT_EQ(out.failedCount, 0) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Contract (decision 4): a wrong-typed id is an invalid option. AlignTool
// converts it with QVariant::toInt(), so "abc" becomes atom 0 and the
// command moves the molecule.
TEST_F(AlignToolCommandTest, knownDeviationNonNumericIdActsOnAtomZero)
{
  recordKnownDeviation("a non-numeric id is read as 0 and moves the molecule");

  const CommandOutcome out = m_harness.run("centerAtom", { { "id", "abc" } });
  EXPECT_TRUE(out.claimed);
  // When these fail, expect status == Failed and nothing moved.
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  // Everything shifted by -H0 = (0, -1, 0).
  EXPECT_EQ(position(0), Vector3(0.0, 0.0, 0.0));
  EXPECT_EQ(position(2), Vector3(1.5, -1.0, 0.0));
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
// AlignTool returns false for a tool with no molecule, whether it never had
// one or was detached with setMolecule(nullptr).
TEST_F(AlignToolCommandTest, knownDeviationNoMolecule)
{
  recordKnownDeviation("with no molecule commands return false");

  AlignTool fresh;
  // When these fail, expect true and commandFailed("No molecule").
  EXPECT_FALSE(fresh.handleCommand("centerAtom", { { "id", qlonglong(0) } }));
  EXPECT_FALSE(fresh.handleCommand("notACommand", {}));

  const MoleculeSnapshot before = m_harness.snapshot();
  m_harness.setPluginMolecule(nullptr);
  const CommandOutcome out =
    m_harness.run("centerAtom", { { "id", qlonglong(2) } });
  // When this fails, expect claimed and commandFailed("No molecule").
  EXPECT_FALSE(out.claimed);
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

// Not settled by the decisions: aligning an atom that sits at the origin has
// no direction to rotate, and AlignTool claims the command and does nothing.
TEST_F(AlignToolCommandTest, undecidedAlignAtomAtOriginIsSilentNoOp)
{
  recordUndecided("alignAtom on an atom at the origin returns true and "
                  "does nothing");

  const MoleculeSnapshot before = m_harness.snapshot();
  const CommandOutcome out =
    m_harness.run("alignAtom", { { "id", qlonglong(1) }, { "axis", "x" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(m_harness.snapshot(), before);
}
