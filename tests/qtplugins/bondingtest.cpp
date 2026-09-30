/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "bonding.h"

#include <QtCore/QSettings>

#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

using Avogadro::Index;
using Avogadro::Vector3;
using Avogadro::QtPlugins::Bonding;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::MoleculeSnapshot;
using Avogadro::QtPluginsTests::recordKnownDeviation;

using BondList = std::vector<std::pair<Index, Index>>;

namespace {

class BondingCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // Bonding reads its tolerance (default 0.45 A) and minimum distance
    // (default 0.32 A) from QSettings in its constructor; the golden bond
    // lists below assume the defaults.
    QSettings settings;
    settings.remove("bonding/tolerance");
    settings.remove("bonding/minDistance");
    m_bonding = std::make_unique<Bonding>();

    m_harness.buildPeroxideChain();
    m_harness.attach(m_bonding.get());
    m_harness.registerCommands();
  }

  // Ethylene, all bonds entered as single: C0 C1, H2 H3 on C0, H4 H5 on C1.
  void buildEthyleneAllSingle()
  {
    m_harness.buildEmpty();
    auto* mol = m_harness.molecule();
    mol->addAtom(6, Vector3(0.0, 0.0, 0.0));
    mol->addAtom(6, Vector3(1.33, 0.0, 0.0));
    mol->addAtom(1, Vector3(-0.57, 0.93, 0.0));
    mol->addAtom(1, Vector3(-0.57, -0.93, 0.0));
    mol->addAtom(1, Vector3(1.90, 0.93, 0.0));
    mol->addAtom(1, Vector3(1.90, -0.93, 0.0));
    mol->addBond(0, 1, 1);
    mol->addBond(0, 2, 1);
    mol->addBond(0, 3, 1);
    mol->addBond(1, 4, 1);
    mol->addBond(1, 5, 1);
  }

  // Declared before the harness, so it outlives it.
  std::unique_ptr<Bonding> m_bonding;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(BondingCommandTest, registersDocumentedCommands)
{
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  EXPECT_EQ(registered.keys(),
            QStringList({ "addBondOrders", "createBonds", "removeBonds" }));
}

TEST_F(BondingCommandTest, removeBondsWithNoSelectionRemovesAll)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  const CommandOutcome out = m_harness.run("removeBonds");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  const MoleculeSnapshot after = m_harness.snapshot();
  EXPECT_TRUE(after.bondPairs.empty());
  EXPECT_EQ(before.differences(after, false), QStringList({ "bonds" }));
}

// With a selection, only bonds touching a selected atom go: selecting H0
// removes H0-O1 and leaves O1-O2, O2-H3.
TEST_F(BondingCommandTest, removeBondsWithSelectionRemovesOnlyThose)
{
  m_harness.molecule()->setAtomSelected(0, true);
  const CommandOutcome out = m_harness.run("removeBonds");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  // Removal swaps the last bond into the freed slot, so compare as a set.
  BondList bonds = m_harness.snapshot().bondPairs;
  std::sort(bonds.begin(), bonds.end());
  EXPECT_EQ(bonds, BondList({ { 1, 2 }, { 2, 3 } }));
}

// Bond if d < r_cov(i) + r_cov(j) + 0.45 A (and d > 0.32 A), never H-H.
// Pyykko covalent radii: H 0.32, O 0.63.
//   O-H cutoff 1.40 A: H0-O1 = O2-H3 = 1.0 -> bonded;
//                      H0-O2 = O1-H3 = sqrt(1.5^2 + 1) = 1.803 -> not.
//   O-O cutoff 1.71 A: O1-O2 = 1.5 -> bonded.
// So exactly the chain 0-1, 1-2, 2-3, in that (i < j loop) order, order 1.
TEST_F(BondingCommandTest, createBondsPerceivesTheChain)
{
  ASSERT_EQ(m_harness.run("removeBonds").status, CommandStatus::Finished);
  ASSERT_TRUE(m_harness.snapshot().bondPairs.empty());

  const CommandOutcome out = m_harness.run("createBonds");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  const MoleculeSnapshot after = m_harness.snapshot();
  EXPECT_EQ(after.bondPairs, BondList({ { 0, 1 }, { 1, 2 }, { 2, 3 } }));
  EXPECT_EQ(after.bondOrders, std::vector<unsigned char>({ 1, 1, 1 }));
}

// Ethylene: each carbon has three sigma bonds and valence 4, so the one
// unsaturated valence on each is satisfied by making C0=C1 double. The C-H
// bonds stay single.
TEST_F(BondingCommandTest, addBondOrdersMakesEthyleneDouble)
{
  buildEthyleneAllSingle();
  const MoleculeSnapshot before = m_harness.snapshot();
  const CommandOutcome out = m_harness.run("addBondOrders");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  const MoleculeSnapshot after = m_harness.snapshot();
  EXPECT_EQ(after.bondPairs, before.bondPairs);
  EXPECT_EQ(after.bondOrders, std::vector<unsigned char>({ 2, 1, 1, 1, 1 }));
}

TEST_F(BondingCommandTest, unknownCommandIsNotClaimed)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  for (const char* name : { "notACommand", "RemoveBonds", "selectAll" }) {
    const CommandOutcome out = m_harness.run(name);
    EXPECT_FALSE(out.claimed) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Every mutating command must be undoable. Bonding edits the QtGui::Molecule
// directly, bypassing RWMolecule, so nothing reaches the undo stack and undo
// cannot bring the bonds back.
TEST_F(BondingCommandTest, knownDeviationEditsAreNotUndoable)
{
  recordKnownDeviation("removeBonds, createBonds and addBondOrders push no "
                       "undo entry");

  const MoleculeSnapshot before = m_harness.snapshot();
  ASSERT_EQ(before.undoCount, 0);
  ASSERT_EQ(m_harness.run("removeBonds").status, CommandStatus::Finished);
  // When these fail, expect undoCount 1 and undo() to restore `before`.
  EXPECT_EQ(m_harness.snapshot().undoCount, 0);
  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_TRUE(m_harness.snapshot().bondPairs.empty());

  ASSERT_EQ(m_harness.run("createBonds").status, CommandStatus::Finished);
  EXPECT_EQ(m_harness.snapshot().undoCount, 0);

  buildEthyleneAllSingle();
  ASSERT_EQ(m_harness.run("addBondOrders").status, CommandStatus::Finished);
  EXPECT_EQ(m_harness.snapshot().bondOrders[0], 2);
  EXPECT_EQ(m_harness.snapshot().undoCount, 0);
}

// Contract (decision 1): no molecule -> true + commandFailed("No molecule").
TEST_F(BondingCommandTest, knownDeviationNoMoleculeIsNotClaimed)
{
  recordKnownDeviation("with no molecule every command returns false");

  const MoleculeSnapshot before = m_harness.snapshot();
  m_harness.setPluginMolecule(nullptr);
  for (const char* name : { "removeBonds", "createBonds", "addBondOrders" }) {
    const CommandOutcome out = m_harness.run(name);
    // When this fails, expect claimed, Failed, NoMoleculeMessage.
    EXPECT_FALSE(out.claimed) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// A finding, not a contract case: createBonds re-adds existing bonds with
// order 1, and Core::Molecule::addBond() updates the order of an existing
// bond, so perceived double bonds are silently demoted.
TEST_F(BondingCommandTest, createBondsResetsExistingBondOrders)
{
  ::testing::Test::RecordProperty(
    "finding", "createBonds demotes existing multiple bonds to single");

  buildEthyleneAllSingle();
  ASSERT_EQ(m_harness.run("addBondOrders").status, CommandStatus::Finished);
  ASSERT_EQ(m_harness.snapshot().bondOrders[0], 2);

  const CommandOutcome out = m_harness.run("createBonds");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(m_harness.snapshot().bondOrders[0], 1);
}
