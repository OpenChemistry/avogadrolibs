/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "resetview.h"

#include <avogadro/rendering/camera.h>

#include <gtest/gtest.h>

using Avogadro::Vector3;
using Avogadro::Vector3f;
using Avogadro::QtPlugins::ResetView;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::MoleculeSnapshot;
using Avogadro::QtPluginsTests::NoMoleculeMessage;
using Avogadro::Rendering::Camera;

namespace {

constexpr float CamTol = 1e-4f;

class ResetViewCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildEmpty();
    m_harness.attach(&m_resetView);
    m_resetView.setCamera(&m_camera);
    m_harness.registerCommands();
  }

  // Where the camera is located, in model/world coordinates.
  Vector3f eye() const { return m_camera.modelView().inverse().translation(); }

  Camera m_camera;
  ResetView m_resetView;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(ResetViewCommandTest, registersDocumentedCommands)
{
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  EXPECT_EQ(registered.keys(), QStringList({ "alignView" }));
}

TEST_F(ResetViewCommandTest, noMoleculeFails)
{
  m_harness.setPluginMolecule(nullptr);
  const CommandOutcome out = m_harness.run("alignView");
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed);
  EXPECT_EQ(out.message, QString(NoMoleculeMessage));
  EXPECT_TRUE(out.clean()) << describe(out);
}

TEST_F(ResetViewCommandTest, noCameraFails)
{
  m_resetView.setCamera(nullptr);
  m_harness.buildMethanol();
  const CommandOutcome out = m_harness.run("alignView");
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed);
  EXPECT_EQ(out.message, QStringLiteral("No camera"));
  EXPECT_TRUE(out.clean()) << describe(out);
}

TEST_F(ResetViewCommandTest, rejectsUnknownOption)
{
  m_harness.buildMethanol();
  QVariantMap badOptions;
  badOptions.insert(QStringLiteral("extra"), 42);
  const auto outcome = m_harness.run("alignView", badOptions);
  EXPECT_EQ(outcome.status, CommandStatus::Failed) << describe(outcome);
}

TEST_F(ResetViewCommandTest, rejectsInvalidAxis)
{
  m_harness.buildMethanol();
  QVariantMap badOptions;
  badOptions.insert(QStringLiteral("axis"), QStringLiteral("w"));
  const auto outcome = m_harness.run("alignView", badOptions);
  EXPECT_EQ(outcome.status, CommandStatus::Failed) << describe(outcome);
}

TEST_F(ResetViewCommandTest, alignViewDefaultZAxis)
{
  auto* mol = m_harness.molecule();
  mol->addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol->addAtom(6, Vector3(2.0, 0.0, 0.0));
  const MoleculeSnapshot before = m_harness.snapshot();

  // Run with default axis (should default to "z")
  const CommandOutcome out = m_harness.run("alignView");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);

  // Molecule geometry and undo stack remain untouched
  EXPECT_EQ(m_harness.snapshot().differences(before), QStringList());

  // Camera forward is +Z, so eye is located along +Z from midpoint (1.0, 0.0,
  // 0.0)
  const Vector3f cameraPos = eye();
  EXPECT_NEAR(cameraPos.x(), 1.0f, CamTol);
  EXPECT_NEAR(cameraPos.y(), 0.0f, CamTol);
  EXPECT_GT(cameraPos.z(), 0.0f);
}

TEST_F(ResetViewCommandTest, alignViewXAxis)
{
  auto* mol = m_harness.molecule();
  mol->addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol->addAtom(6, Vector3(0.0, 2.0, 0.0));
  const MoleculeSnapshot before = m_harness.snapshot();

  const CommandOutcome out = m_harness.run("alignView", { { "axis", "x" } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);

  EXPECT_EQ(m_harness.snapshot().differences(before), QStringList());

  // Camera forward is +X, so eye is located along +X from midpoint (0.0, 1.0,
  // 0.0)
  const Vector3f cameraPos = eye();
  EXPECT_GT(cameraPos.x(), 0.0f);
  EXPECT_NEAR(cameraPos.y(), 1.0f, CamTol);
  EXPECT_NEAR(cameraPos.z(), 0.0f, CamTol);
}

TEST_F(ResetViewCommandTest, alignViewYAxis)
{
  auto* mol = m_harness.molecule();
  mol->addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol->addAtom(6, Vector3(0.0, 0.0, 2.0));
  const MoleculeSnapshot before = m_harness.snapshot();

  const CommandOutcome out = m_harness.run("alignView", { { "axis", "y" } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);

  EXPECT_EQ(m_harness.snapshot().differences(before), QStringList());

  // Camera forward is +Y, so eye is located along +Y from midpoint (0.0,
  // 0.0, 1.0)
  const Vector3f cameraPos = eye();
  EXPECT_NEAR(cameraPos.x(), 0.0f, CamTol);
  EXPECT_GT(cameraPos.y(), 0.0f);
  EXPECT_NEAR(cameraPos.z(), 1.0f, CamTol);
}
