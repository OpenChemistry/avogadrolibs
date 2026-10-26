/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "constraintsextension.h"

#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>

#include <gtest/gtest.h>

using Avogadro::QtPlugins::ConstraintsExtension;
using Avogadro::QtPluginsTests::atomList;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::NoMoleculeMessage;

namespace {

// Peroxide chain H0 (0,1,0) O1 (0,0,0) O2 (1.5,0,0) H3 (1.5,0,1).
class ConstraintsCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildPeroxideChain();
    m_harness.attach(&m_plugin);
    m_harness.registerCommands();
  }

  ConstraintsExtension m_plugin;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(ConstraintsCommandTest, registersDocumentedCommands)
{
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty());
  for (const char* name : { "listConstraints", "addConstraint",
                            "removeConstraint", "clearConstraints" })
    EXPECT_TRUE(registered.contains(name)) << name;
  EXPECT_EQ(registered.size(), 4);
}

TEST_F(ConstraintsCommandTest, addListRemoveClear)
{
  // Measured default for a distance.
  CommandOutcome out =
    m_harness.run("addConstraint", { { "atoms", atomList({ 1, 2 }) } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("type").toString(), "distance");
  EXPECT_NEAR(out.result.value("value").toDouble(), 1.5, 1e-9);
  EXPECT_FALSE(out.result.value("updated").toBool());

  // Same atoms, reversed, updates rather than duplicates.
  out = m_harness.run("addConstraint",
                      { { "atoms", atomList({ 2, 1 }) }, { "value", 2.0 } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.result.value("updated").toBool());

  out = m_harness.run("addConstraint",
                      { { "atoms", atomList({ 0, 1, 2 }) }, { "value", 100 } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("type").toString(), "angle");

  out = m_harness.run("listConstraints");
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("constraints").toList().size(), 2);

  out = m_harness.run("removeConstraint", { { "atoms", atomList({ 1, 2 }) } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("removed").toLongLong(), 1);
  out = m_harness.run("removeConstraint", { { "atoms", atomList({ 1, 2 }) } });
  EXPECT_EQ(out.status, CommandStatus::Failed);

  out = m_harness.run("clearConstraints");
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("removed").toLongLong(), 1);
}

TEST_F(ConstraintsCommandTest, invalidOptionsFail)
{
  const std::vector<std::pair<const char*, QVariantMap>> invalid = {
    { "addConstraint", {} },
    { "addConstraint", { { "atoms", atomList({ 0 }) } } },
    { "addConstraint", { { "atoms", atomList({ 0, 1, 2, 3, 0 }) } } },
    { "addConstraint", { { "atoms", atomList({ 0, 0 }) } } },
    { "addConstraint", { { "atoms", atomList({ 0, 9 }) } } },
    { "addConstraint", { { "atoms", atomList({ 0, 1 }) }, { "value", "1" } } },
    { "addConstraint", { { "atoms", atomList({ 0, 1 }) }, { "value", 0.0 } } },
    { "addConstraint",
      { { "atoms", atomList({ 0, 1, 2 }) }, { "value", 181 } } },
    { "removeConstraint", { { "atoms", atomList({ 0, 1 }) }, { "value", 1 } } },
    { "listConstraints", { { "x", 1 } } },
    { "clearConstraints", { { "x", 1 } } },
  };
  for (const auto& [name, options] : invalid) {
    const CommandOutcome out = m_harness.run(name, options);
    EXPECT_TRUE(out.claimed) << name;
    EXPECT_EQ(out.status, CommandStatus::Failed) << name << describe(out);
    EXPECT_EQ(out.failedCount, 1) << name;
  }
  // None of that left a constraint behind.
  EXPECT_TRUE(m_harness.run("listConstraints")
                .result.value("constraints")
                .toList()
                .isEmpty());
}

TEST_F(ConstraintsCommandTest, noMoleculeFails)
{
  m_harness.setPluginMolecule(nullptr);
  const CommandOutcome out = m_harness.run("listConstraints");
  EXPECT_EQ(out.status, CommandStatus::Failed);
  EXPECT_EQ(out.message, QString(NoMoleculeMessage));
}

TEST_F(ConstraintsCommandTest, commandSchema)
{
  const QJsonObject add = m_plugin.commandSchema("addConstraint");
  ASSERT_FALSE(add.isEmpty());
  const QJsonObject props = add["properties"].toObject();
  EXPECT_EQ(props["atoms"].toObject()["minItems"].toInt(), 2);
  EXPECT_EQ(props["atoms"].toObject()["maxItems"].toInt(), 4);
  EXPECT_EQ(props["value"].toObject()["type"].toString(), "number");
  EXPECT_EQ(add["required"].toArray(), QJsonArray{ "atoms" });
  EXPECT_FALSE(add["additionalProperties"].toBool(true));

  EXPECT_TRUE(m_plugin.commandSchema("clearConstraints")["properties"]
                .toObject()
                .isEmpty());
  EXPECT_TRUE(m_plugin.commandSchema("notACommand").isEmpty());
}
