/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
 ******************************************************************************/

#include "commandtestharness.h"

#include "symmetry.h"

#include <avogadro/qtgui/rwmolecule.h>

#include <gtest/gtest.h>

using Avogadro::Vector3;
using Avogadro::QtPlugins::Symmetry;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::MoleculeSnapshot;
using Avogadro::QtPluginsTests::NoMoleculeMessage;

namespace {

class SymmetryCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    buildWater();
    m_harness.attach(&m_symmetry);
    m_harness.registerCommands();
  }

  void buildWater()
  {
    m_harness.buildEmpty();
    auto& rw = *m_harness.molecule()->undoMolecule();
    auto a0 = rw.addAtom(8);
    a0.setPosition3d(Vector3(0.0, 0.0, 0.117));
    auto a1 = rw.addAtom(1);
    a1.setPosition3d(Vector3(0.0, 0.757, -0.469));
    auto a2 = rw.addAtom(1);
    a2.setPosition3d(Vector3(0.0, -0.757, -0.469));
  }

  Symmetry m_symmetry;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(SymmetryCommandTest, registersDocumentedCommands)
{
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  QStringList expected = { "detectSymmetry", "symmetrize" };
  expected.sort();
  auto actual = registered.keys();
  actual.sort();
  EXPECT_EQ(actual, expected);
}

TEST_F(SymmetryCommandTest, noMoleculeFails)
{
  m_harness.setPluginMolecule(nullptr);
  for (const auto& cmd : { "detectSymmetry", "symmetrize" }) {
    const auto out = m_harness.run(cmd);
    EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
    EXPECT_EQ(out.message, NoMoleculeMessage);
    EXPECT_TRUE(out.clean()) << describe(out);
  }
}

TEST_F(SymmetryCommandTest, rejectsUnknownOption)
{
  for (const auto& cmd : { "detectSymmetry", "symmetrize" }) {
    const auto out = m_harness.run(cmd, { { "invalidOpt", 123 } });
    EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
    EXPECT_TRUE(out.message.contains("unknown option")) << describe(out);
    EXPECT_TRUE(out.clean()) << describe(out);
  }
}

TEST_F(SymmetryCommandTest, rejectsInvalidTolerance)
{
  for (const auto& cmd : { "detectSymmetry", "symmetrize" }) {
    const auto out = m_harness.run(cmd, { { "tolerance", "superloose" } });
    EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
    EXPECT_TRUE(out.message.contains("tolerance must be one of"))
      << describe(out);
    EXPECT_TRUE(out.clean()) << describe(out);
  }
}

TEST_F(SymmetryCommandTest, detectSymmetryDefaultTolerance)
{
  const auto out = m_harness.run("detectSymmetry");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("pointGroup").toString(), "C2v");
  EXPECT_TRUE(out.message.contains("C2v")) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
}

TEST_F(SymmetryCommandTest, detectSymmetryExplicitTolerances)
{
  for (const auto& tol : { "loose", "normal", "tight", "veryloose" }) {
    const auto out = m_harness.run("detectSymmetry", { { "tolerance", tol } });
    EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
    EXPECT_EQ(out.result.value("pointGroup").toString(), "C2v");
    EXPECT_TRUE(out.clean()) << describe(out);
  }
}

TEST_F(SymmetryCommandTest, detectSymmetrySingleAtom)
{
  m_harness.buildEmpty();
  auto& rw = *m_harness.molecule()->undoMolecule();
  rw.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));

  const auto out = m_harness.run("detectSymmetry");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("pointGroup").toString(), "Kh");
  EXPECT_TRUE(out.clean()) << describe(out);
}

TEST_F(SymmetryCommandTest, symmetrizeSingleAtomFails)
{
  m_harness.buildEmpty();
  auto& rw = *m_harness.molecule()->undoMolecule();
  rw.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));

  const auto out = m_harness.run("symmetrize");
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_TRUE(out.message.contains("already symmetric")) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
}

TEST_F(SymmetryCommandTest, symmetrizeSlightlyDistortedMolecule)
{
  // Slightly perturb one H atom
  auto& rw = *m_harness.molecule()->undoMolecule();
  rw.atom(1).setPosition3d(Vector3(0.005, 0.755, -0.465));

  const auto out = m_harness.run("symmetrize", { { "tolerance", "loose" } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("pointGroup").toString(), "C2v");
  EXPECT_TRUE(out.result.contains("symmetryError"));
  EXPECT_GT(out.result.value("symmetryError").toDouble(), 0.0);
  EXPECT_TRUE(out.clean()) << describe(out);

  // Invariant: one undo step restores original
  m_harness.undo();
  EXPECT_EQ(m_harness.molecule()->atomPosition3d(1),
            Vector3(0.005, 0.755, -0.465));
}
