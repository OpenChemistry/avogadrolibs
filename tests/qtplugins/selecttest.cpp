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
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::MoleculeSnapshot;
using Avogadro::QtPluginsTests::NoMoleculeMessage;
using Avogadro::QtPluginsTests::recordKnownDeviation;

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
TEST_F(SelectCommandTest, invalidElementFails)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  // Not "Xx": that is the dummy-atom symbol (Z = 0), which Select accepts
  // by symbol although it rejects 0 as a number.
  const std::vector<QVariantMap> invalid = {
    {},                                // missing key
    { { "element", "Qq" } },           // unknown symbol
    { { "element", qlonglong(0) } },   // atomic number out of range
    { { "element", qlonglong(-6) } },  // negative
    { { "element", qlonglong(999) } }, // past the last element
    { { "element", QVariantList() } }, // wrong type
  };
  for (const QVariantMap& options : invalid) {
    const CommandOutcome out = m_harness.run("selectElement", options);
    const std::string key = options.value("element").toString().toStdString();
    EXPECT_TRUE(out.claimed) << key;
    EXPECT_EQ(out.status, CommandStatus::Failed) << key;
    EXPECT_EQ(out.failedCount, 1) << key;
    EXPECT_FALSE(out.message.isEmpty()) << key;
    EXPECT_TRUE(out.clean()) << key << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Contract (decision 1): with no molecule a recognized command returns true
// and emits commandFailed("No molecule").
TEST_F(SelectCommandTest, noMoleculeFails)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  m_harness.setPluginMolecule(nullptr);
  for (const char* name :
       { "selectAll", "selectElement", "createLayerFromSelection" }) {
    const CommandOutcome out = m_harness.run(name, { { "element", "O" } });
    EXPECT_TRUE(out.claimed) << name;
    EXPECT_EQ(out.status, CommandStatus::Failed) << name;
    EXPECT_EQ(out.message, QString(NoMoleculeMessage)) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Every Select command reports the resulting selection as
// commandFinished(result) with result["indices"] (#3077).
TEST_F(SelectCommandTest, resultReportsSelectedIndices)
{
  CommandOutcome out = m_harness.run("selectElement", { { "element", "H" } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.finishedCount, 1);
  EXPECT_EQ(out.result.value("indices").toList(), QVariantList({ 2, 3, 4, 5 }));

  out = m_harness.run("invertSelection");
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("indices").toList(), QVariantList({ 0, 1 }));

  out = m_harness.run("selectNone");
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.result.contains("indices"));
  EXPECT_TRUE(out.result.value("indices").toList().isEmpty());
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

// Release plan section 4.2 sequence. Consecutive selection changes merge into
// one undo step (RWMolecule's ModifySelectionCommand), so the three commands
// leave a single step whose undo returns to "nothing selected".
TEST_F(SelectCommandTest, selectAllInvertInvertSequence)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  ASSERT_TRUE(before.selectedIndices().empty());
  const std::vector<Index> all = { 0, 1, 2, 3, 4, 5 };

  CommandOutcome out = m_harness.run("selectAll");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(m_harness.snapshot().selectedIndices(), all);

  out = m_harness.run("invertSelection");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_TRUE(m_harness.snapshot().selectedIndices().empty());

  out = m_harness.run("invertSelection");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  const MoleculeSnapshot after = m_harness.snapshot();
  EXPECT_EQ(after.selectedIndices(), all);
  EXPECT_EQ(before.differences(after, false), QStringList({ "selection" }));
  EXPECT_EQ(after.undoCount, before.undoCount + 1);

  QStringList violations = m_harness.undo();
  EXPECT_TRUE(violations.isEmpty()) << violations.join("; ").toStdString();
  EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());

  violations = m_harness.redo();
  EXPECT_TRUE(violations.isEmpty()) << violations.join("; ").toStdString();
  EXPECT_EQ(m_harness.snapshot().differences(after), QStringList());
}

// Contract (decision 2): a command that changes nothing must not push an
// undo entry. RWMolecule::setAtomSelected() pushed one even when the atom was
// already in the requested state (fixed on branch fix-selection-noop-undo).
// Each case starts from a fresh molecule, so the empty undo stack gives the
// no-op entry nothing to merge into.
TEST_F(SelectCommandTest, knownDeviationNoOpSelectionPushesUndoEntry)
{
  recordKnownDeviation(
    "a selection command that changes nothing pushes an undo entry");

  const std::vector<std::pair<const char*, QVariantMap>> noOps = {
    { "selectNone", {} },                        // nothing selected
    { "selectElement", { { "element", "U" } } }, // valid, no uranium
    { "selectElement", { { "element", qlonglong(92) } } },
  };
  for (const auto& [name, options] : noOps) {
    m_harness.buildMethanol();
    const MoleculeSnapshot before = m_harness.snapshot();
    ASSERT_EQ(before.undoCount, 0);

    const CommandOutcome out = m_harness.run(name, options);
    EXPECT_EQ(out.status, CommandStatus::Finished) << name;
    const MoleculeSnapshot after = m_harness.snapshot();
    EXPECT_EQ(before.differences(after, false), QStringList()) << name;
    // When these fail, the no-op no longer pushes anything: expect
    // out.clean() and after == before instead.
    EXPECT_EQ(after.undoCount, 1) << name;
    EXPECT_FALSE(out.clean()) << name;
  }
}

// Decided: createLayerFromSelection must put the layer on the plugin's own
// molecule, making it the active one first if it is not. Currently
// RWLayerManager::addLayer() adds the layer to whichever molecule is active
// (fixed on branch fix-layer-from-selection-active).
TEST_F(SelectCommandTest,
       knownDeviationCreateLayerOnInactiveMoleculeGoesToActiveOne)
{
  recordKnownDeviation("createLayerFromSelection adds the layer to the active "
                       "molecule, not the plugin's");

  ASSERT_EQ(m_harness.run("selectElement", { { "element", "O" } }).status,
            CommandStatus::Finished);

  // Another window's molecule is active; the plugin still has ours.
  Avogadro::QtGui::Molecule other;
  other.addAtom(6);
  other.addAtom(6);
  m_harness.setActiveLayerMolecule(&other);
  ASSERT_FALSE(m_harness.harnessMoleculeIsActive());

  const CommandOutcome out = m_harness.run("createLayerFromSelection");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);

  const MoleculeSnapshot after = m_harness.snapshot();
  // When these fail, the fix has landed: expect our molecule to be active,
  // after.maxLayer == 1, O (atom 1) in layer 1, other.layer().maxLayer() == 0.
  EXPECT_FALSE(m_harness.harnessMoleculeIsActive());
  EXPECT_EQ(after.maxLayer, 0u);
  EXPECT_EQ(after.layerIds, std::vector<size_t>(6, 0));
  EXPECT_EQ(other.layer().maxLayer(), 1u);

  m_harness.setActiveLayerMolecule(nullptr);
}
