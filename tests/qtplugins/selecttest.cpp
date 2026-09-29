/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "select.h"

#include <avogadro/core/layer.h>

#include <gtest/gtest.h>

#include <vector>

using Avogadro::Index;
using Avogadro::QtPlugins::Select;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::MoleculeSnapshot;

namespace {

// Methanol from CommandTestHarness::buildMethanol(): C0 O1 H2 H3 H4 H5.
class SelectCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildMethanol();
    m_harness.attach(&m_select);
    m_harness.registerCommands();
  }

  Select m_select;
  CommandTestHarness m_harness;
};

std::string describe(const CommandOutcome& out)
{
  return std::string("status ") + toString(out.status) + ", violations: " +
         out.violations.join(QStringLiteral("; ")).toStdString();
}

// Records a behaviour that differs from the command outcome contract (2.1
// release plan, section 2, decision 2) in the test XML, so the deviations can
// be listed from a CI run. The test body asserts the current behaviour, so it
// fails -- and must be rewritten to the contract -- once the plugin is fixed.
void recordKnownDeviation(const char* what)
{
  ::testing::Test::RecordProperty("known_deviation", what);
}

} // namespace

TEST_F(SelectCommandTest, registersDocumentedCommands)
{
  const QStringList expected = {
    "selectAll",       "selectNone",
    "invertSelection", "selectElement",
    "selectBackbone",  "selectSidechains",
    "selectWater",     "enlargeSelection",
    "shrinkSelection", "createLayerFromSelection"
  };

  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  EXPECT_EQ(registered.keys().size(), expected.size());
  for (const QString& name : expected)
    EXPECT_TRUE(registered.contains(name)) << name.toStdString();
}

TEST_F(SelectCommandTest, selectElementBySymbol)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  ASSERT_TRUE(before.selectedIndices().empty());

  const CommandOutcome out =
    m_harness.run("selectElement", { { "element", "O" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_FALSE(out.async);
  EXPECT_TRUE(out.clean()) << describe(out);

  const MoleculeSnapshot after = m_harness.snapshot();
  EXPECT_EQ(after.selectedIndices(), std::vector<Index>({ 1 }));
  // Only the selection (and its undo entries) changed.
  const QStringList changed = before.differences(after, false);
  EXPECT_EQ(changed, QStringList({ "selection" }));
  EXPECT_GT(after.undoIndex, before.undoIndex);
}

TEST_F(SelectCommandTest, selectElementByAtomicNumber)
{
  // A JSON number arrives as a qlonglong or double, never an int.
  const CommandOutcome out =
    m_harness.run("selectElement", { { "element", qlonglong(1) } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(m_harness.snapshot().selectedIndices(),
            std::vector<Index>({ 2, 3, 4, 5 }));
}

TEST_F(SelectCommandTest, unknownCommandIsNotClaimed)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  // Nonsense, a case variant, and another plugin's command.
  for (const char* name : { "notACommand", "SelectAll", "measureDistance" }) {
    const CommandOutcome out = m_harness.run(name);
    EXPECT_FALSE(out.claimed) << name;
    EXPECT_EQ(out.status, CommandStatus::NotHandled) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Contract: a recognized command with invalid options returns true and
// emits commandFailed(), leaving the molecule untouched.
// Select predates the contract: it returns false ("not my command") and
// emits nothing, so an RPC caller is told the method does not exist.
TEST_F(SelectCommandTest, knownDeviationInvalidElementIsNotClaimed)
{
  recordKnownDeviation(
    "selectElement with a missing or invalid element returns false and "
    "emits no commandFailed()");

  const MoleculeSnapshot before = m_harness.snapshot();
  // Not "Xx": that is the dummy-atom symbol (Z = 0), which Select accepts
  // by symbol although it rejects 0 as a number.
  const std::vector<QVariantMap> invalid = {
    {},                                // missing key
    { { "element", "Qq" } },           // unknown symbol
    { { "element", qlonglong(0) } },   // atomic number out of range
    { { "element", qlonglong(-6) } },  // negative
    { { "element", QVariantList() } }, // wrong type
  };
  for (const QVariantMap& options : invalid) {
    const CommandOutcome out = m_harness.run("selectElement", options);
    const QString key = options.value("element").toString();
    // When these fail, Select has been brought into line: replace them with
    // claimed == true and status == Failed.
    EXPECT_FALSE(out.claimed) << key.toStdString();
    EXPECT_EQ(out.failedCount, 0) << key.toStdString();
    // Independent of the deviation: nothing may change.
    EXPECT_TRUE(out.clean()) << key.toStdString() << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Not a contract case the plan decides (see the design note's open
// questions): measuretool and symmetry claim the command and fail it, while
// Select, like most older plugins, returns false without a molecule.
TEST_F(SelectCommandTest, knownDeviationNoMoleculeIsNotClaimed)
{
  recordKnownDeviation("with no molecule every command returns false");

  const MoleculeSnapshot before = m_harness.snapshot();
  m_harness.setPluginMolecule(nullptr);
  for (const char* name :
       { "selectAll", "selectElement", "createLayerFromSelection" }) {
    const CommandOutcome out = m_harness.run(name, { { "element", "O" } });
    EXPECT_FALSE(out.claimed) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

TEST_F(SelectCommandTest, createLayerFromSelectionUndoRedo)
{
  ASSERT_EQ(m_harness.run("selectElement", { { "element", "O" } }).status,
            CommandStatus::Finished);
  const MoleculeSnapshot selected = m_harness.snapshot();
  ASSERT_EQ(selected.maxLayer, 0u);

  const CommandOutcome out = m_harness.run("createLayerFromSelection");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);

  const MoleculeSnapshot layered = m_harness.snapshot();
  EXPECT_EQ(layered.maxLayer, 1u);
  EXPECT_EQ(layered.layerIds, std::vector<size_t>({ 0, 1, 0, 0, 0, 0 }));
  // The selection itself is left alone.
  EXPECT_EQ(layered.selectedIndices(), std::vector<Index>({ 1 }));

  QStringList violations = m_harness.undo();
  EXPECT_TRUE(violations.isEmpty()) << violations.join("; ").toStdString();
  EXPECT_EQ(m_harness.snapshot().differences(selected, false), QStringList())
    << "undo should restore the pre-layer molecule";

  violations = m_harness.redo();
  EXPECT_TRUE(violations.isEmpty()) << violations.join("; ").toStdString();
  EXPECT_EQ(m_harness.snapshot().differences(layered), QStringList())
    << "redo should restore the layered molecule, undo position included";
}
