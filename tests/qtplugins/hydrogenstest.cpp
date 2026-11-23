/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "hydrogens.h"

#include <gtest/gtest.h>

using Avogadro::Index;
using Avogadro::Vector3;
using Avogadro::QtPlugins::Hydrogens;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::MoleculeSnapshot;
using Avogadro::QtPluginsTests::NoMoleculeMessage;

namespace {

class HydrogensCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildEmpty();
    m_harness.attach(&m_hydrogens);
    m_harness.registerCommands();
  }

  Hydrogens m_hydrogens;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(HydrogensCommandTest, registersDocumentedCommands)
{
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  EXPECT_EQ(registered.keys(),
            QStringList({ "addHydrogens", "adjustHydrogens",
                          "removeAllHydrogens", "removeHydrogens" }));
}

TEST_F(HydrogensCommandTest, noMoleculeFails)
{
  m_harness.setPluginMolecule(nullptr);
  for (const char* name : { "addHydrogens", "removeHydrogens",
                            "adjustHydrogens", "removeAllHydrogens" }) {
    const CommandOutcome out = m_harness.run(name);
    EXPECT_TRUE(out.claimed) << name;
    EXPECT_EQ(out.status, CommandStatus::Failed) << name;
    EXPECT_EQ(out.message, QString(NoMoleculeMessage)) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
}

TEST_F(HydrogensCommandTest, rejectsUnknownOption)
{
  m_harness.buildMethanol();
  QVariantMap badOptions;
  badOptions.insert(QStringLiteral("extra"), 42);
  const auto outcome = m_harness.run("addHydrogens", badOptions);
  EXPECT_EQ(outcome.status, CommandStatus::Failed) << describe(outcome);
}

TEST_F(HydrogensCommandTest, noOpLeavesNoUndoStep)
{
  m_harness.buildMethanol();
  const MoleculeSnapshot before = m_harness.snapshot();
  for (const char* name :
       { "addHydrogens", "removeHydrogens", "adjustHydrogens" }) {
    const CommandOutcome out = m_harness.run(name);
    EXPECT_EQ(out.status, CommandStatus::Finished) << name;
    EXPECT_EQ(out.result.value("added").toInt(), 0) << name;
    EXPECT_EQ(out.result.value("removed").toInt(), 0) << name;
  }
  EXPECT_EQ(m_harness.snapshot().undoCount, before.undoCount);
}

TEST_F(HydrogensCommandTest, removeAllHydrogensNoOpLeavesNoUndoStep)
{
  // A single bare carbon atom has no hydrogens.
  auto* mol = m_harness.molecule();
  mol->addAtom(6, Vector3::Zero());
  const MoleculeSnapshot before = m_harness.snapshot();

  const CommandOutcome out = m_harness.run("removeAllHydrogens");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("added").toInt(), 0);
  EXPECT_EQ(out.result.value("removed").toInt(), 0);
  EXPECT_EQ(m_harness.snapshot().undoCount, before.undoCount);
}

TEST_F(HydrogensCommandTest, addHydrogensToMethaneCarbon)
{
  // A single bare carbon atom needs 4 hydrogens.
  auto* mol = m_harness.molecule();
  mol->addAtom(6, Vector3::Zero());
  const MoleculeSnapshot before = m_harness.snapshot();

  const CommandOutcome out = m_harness.run("addHydrogens");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(out.result.value("added").toInt(), 4);
  EXPECT_EQ(out.result.value("removed").toInt(), 0);

  const MoleculeSnapshot after = m_harness.snapshot();
  EXPECT_EQ(after.atomicNumbers.size(), 5u);
  EXPECT_EQ(after.bondPairs.size(), 4u);
  EXPECT_EQ(after.undoCount, before.undoCount + 1);

  // Undo in a single step
  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());
  EXPECT_TRUE(m_harness.redo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(after, false), QStringList());
}

TEST_F(HydrogensCommandTest, removeAllHydrogensFromMethanol)
{
  m_harness.buildMethanol();
  const MoleculeSnapshot before = m_harness.snapshot();
  ASSERT_EQ(before.atomicNumbers.size(), 6u); // C, O, 4 H

  const CommandOutcome out = m_harness.run("removeAllHydrogens");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(out.result.value("added").toInt(), 0);
  EXPECT_EQ(out.result.value("removed").toInt(), 4);

  const MoleculeSnapshot after = m_harness.snapshot();
  EXPECT_EQ(after.atomicNumbers.size(), 2u); // C and O remaining
  EXPECT_EQ(after.undoCount, before.undoCount + 1);

  // Undo in a single step
  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());
  EXPECT_TRUE(m_harness.redo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(after, false), QStringList());
}

TEST_F(HydrogensCommandTest, removeExtraHydrogens)
{
  // Build a carbon with 5 bonded hydrogens (overbonded by 1).
  auto* mol = m_harness.molecule();
  mol->addAtom(6, Vector3::Zero());
  for (int i = 0; i < 5; ++i) {
    Index hIdx =
      mol->addAtom(1, Vector3(0.0, 0.0, static_cast<double>(i + 1))).index();
    mol->addBond(0, hIdx, 1);
  }
  const MoleculeSnapshot before = m_harness.snapshot();
  ASSERT_EQ(before.atomicNumbers.size(), 6u);

  const CommandOutcome out = m_harness.run("removeHydrogens");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(out.result.value("added").toInt(), 0);
  EXPECT_EQ(out.result.value("removed").toInt(), 1);

  const MoleculeSnapshot after = m_harness.snapshot();
  EXPECT_EQ(after.atomicNumbers.size(), 5u); // 1 C + 4 H
  EXPECT_EQ(after.undoCount, before.undoCount + 1);

  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());
  EXPECT_TRUE(m_harness.redo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(after, false), QStringList());
}

TEST_F(HydrogensCommandTest, adjustHydrogensAddsAndRemoves)
{
  // C0 is overbonded (1 C + 5 H, valency diff -2), C1 is underbonded (1 C + 1
  // H, valency diff +2). C0 gets 2 H removed, C1 gets 2 H added.
  auto* mol = m_harness.molecule();
  mol->addAtom(6, Vector3(0.0, 0.0, 0.0)); // C0
  mol->addAtom(6, Vector3(1.5, 0.0, 0.0)); // C1
  mol->addBond(0, 1, 1);

  // 5 H on C0
  for (int i = 0; i < 5; ++i) {
    Index hIdx =
      mol->addAtom(1, Vector3(-1.0, static_cast<double>(i), 0.0)).index();
    mol->addBond(0, hIdx, 1);
  }
  // 1 H on C1
  Index hIdx = mol->addAtom(1, Vector3(2.5, 0.0, 0.0)).index();
  mol->addBond(1, hIdx, 1);

  const MoleculeSnapshot before = m_harness.snapshot();
  ASSERT_EQ(before.atomicNumbers.size(), 8u); // 2 C + 6 H

  const CommandOutcome out = m_harness.run("adjustHydrogens");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(out.result.value("added").toInt(), 2);
  EXPECT_EQ(out.result.value("removed").toInt(), 2);

  const MoleculeSnapshot after = m_harness.snapshot();
  EXPECT_EQ(after.atomicNumbers.size(), 8u); // 2 C + 6 H (ethane)
  EXPECT_EQ(after.undoCount, before.undoCount + 1);

  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());
  EXPECT_TRUE(m_harness.redo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(after, false), QStringList());
}
