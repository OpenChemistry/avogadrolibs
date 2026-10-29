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

  /// The constraints listed by listConstraints.
  QVariantList constraints()
  {
    return m_harness.run("listConstraints")
      .result.value("constraints")
      .toList();
  }

  int constraintCount() { return static_cast<int>(constraints().size()); }

  /// The listed entry whose atoms are exactly @p atoms, or an empty map.
  QVariantMap findConstraint(const QVariantList& atoms)
  {
    for (const QVariant& entry : constraints()) {
      const QVariantMap map = entry.toMap();
      if (map.value("atoms").toList() == atoms)
        return map;
    }
    return QVariantMap();
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

  // Same atoms, reversed, updates rather than duplicates. The stored atom
  // order is kept, so it is still listed as [1, 2].
  out = m_harness.run("addConstraint",
                      { { "atoms", atomList({ 2, 1 }) }, { "value", 2.0 } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.result.value("updated").toBool());
  EXPECT_EQ(constraintCount(), 1);
  QVariantMap entry = findConstraint(atomList({ 1, 2 }));
  ASSERT_FALSE(entry.isEmpty());
  EXPECT_EQ(entry.value("type").toString(), "distance");
  EXPECT_NEAR(entry.value("value").toDouble(), 2.0, 1e-9);

  out = m_harness.run("addConstraint",
                      { { "atoms", atomList({ 0, 1, 2 }) }, { "value", 100 } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("type").toString(), "angle");
  EXPECT_EQ(constraintCount(), 2);

  // Reversed angle updates in place.
  out = m_harness.run("addConstraint",
                      { { "atoms", atomList({ 2, 1, 0 }) }, { "value", 110 } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.result.value("updated").toBool());
  EXPECT_EQ(constraintCount(), 2);
  entry = findConstraint(atomList({ 0, 1, 2 }));
  ASSERT_FALSE(entry.isEmpty());
  EXPECT_EQ(entry.value("type").toString(), "angle");
  EXPECT_NEAR(entry.value("value").toDouble(), 110.0, 1e-9);

  // A torsion is added once, then updated when given reversed.
  out = m_harness.run("addConstraint", { { "atoms", atomList({ 0, 1, 2, 3 }) },
                                         { "value", 60 } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("type").toString(), "torsion");
  EXPECT_FALSE(out.result.value("updated").toBool());
  EXPECT_EQ(constraintCount(), 3);
  out = m_harness.run("addConstraint", { { "atoms", atomList({ 3, 2, 1, 0 }) },
                                         { "value", 90 } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.result.value("updated").toBool());
  EXPECT_EQ(constraintCount(), 3);
  entry = findConstraint(atomList({ 0, 1, 2, 3 }));
  ASSERT_FALSE(entry.isEmpty());
  EXPECT_EQ(entry.value("type").toString(), "torsion");
  EXPECT_NEAR(entry.value("value").toDouble(), 90.0, 1e-9);

  // Removing the angle with its atoms reversed.
  out =
    m_harness.run("removeConstraint", { { "atoms", atomList({ 2, 1, 0 }) } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("removed").toLongLong(), 1);
  EXPECT_TRUE(findConstraint(atomList({ 0, 1, 2 })).isEmpty());
  EXPECT_EQ(constraintCount(), 2);

  out = m_harness.run("removeConstraint", { { "atoms", atomList({ 1, 2 }) } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("removed").toLongLong(), 1);
  out = m_harness.run("removeConstraint", { { "atoms", atomList({ 1, 2 }) } });
  EXPECT_EQ(out.status, CommandStatus::Failed);

  // Only the torsion is left.
  EXPECT_EQ(constraintCount(), 1);
  out = m_harness.run("clearConstraints");
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("removed").toLongLong(), 1);
  EXPECT_EQ(constraintCount(), 0);
}

TEST_F(ConstraintsCommandTest, removeConstraintRejectsUnknownOption)
{
  CommandOutcome out =
    m_harness.run("addConstraint", { { "atoms", atomList({ 0, 1 }) } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);

  // The constraint exists, so this fails because of the option alone.
  out = m_harness.run("removeConstraint",
                      { { "atoms", atomList({ 0, 1 }) }, { "value", 1 } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_EQ(out.failedCount, 1);
  EXPECT_NE(out.message.indexOf("value"), -1) << out.message.toStdString();
  EXPECT_NE(out.message.indexOf("unknown option"), -1)
    << out.message.toStdString();

  EXPECT_EQ(constraintCount(), 1);
  EXPECT_FALSE(findConstraint(atomList({ 0, 1 })).isEmpty());
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
