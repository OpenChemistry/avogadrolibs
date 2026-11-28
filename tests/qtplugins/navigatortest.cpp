/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
 ******************************************************************************/

#include "commandtestharness.h"

#include "navigator.h"

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>

#include <gtest/gtest.h>

using Avogadro::QtPlugins::Navigator;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::MoleculeSnapshot;
using Avogadro::QtPluginsTests::NoMoleculeMessage;
using Avogadro::Rendering::GLRenderer;

namespace {

class NavigatorCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildMethanol();
    m_harness.attach(&m_navigator);
    m_navigator.setGLRenderer(&m_renderer);
    m_harness.registerCommands();
  }

  GLRenderer m_renderer;
  Navigator m_navigator;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(NavigatorCommandTest, registersDocumentedCommands)
{
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  QStringList names = registered.keys();
  names.sort();
  EXPECT_EQ(names,
            QStringList({ "rotateScene", "translateScene", "zoomScene" }));
}

TEST_F(NavigatorCommandTest, noMoleculeFails)
{
  m_harness.setPluginMolecule(nullptr);

  CommandOutcome out = m_harness.run("rotateScene", { { "x", 10.0 } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed);
  EXPECT_EQ(out.message, QString(NoMoleculeMessage));

  out = m_harness.run("zoomScene", { { "delta", 5.0 } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed);
  EXPECT_EQ(out.message, QString(NoMoleculeMessage));

  out = m_harness.run("translateScene", { { "x", 10.0 } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed);
  EXPECT_EQ(out.message, QString(NoMoleculeMessage));
}

TEST_F(NavigatorCommandTest, noCameraFails)
{
  m_navigator.setGLRenderer(nullptr);

  CommandOutcome out = m_harness.run("rotateScene", { { "x", 10.0 } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed);
  EXPECT_EQ(out.message, QStringLiteral("No camera"));

  out = m_harness.run("zoomScene", { { "delta", 5.0 } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed);
  EXPECT_EQ(out.message, QStringLiteral("No camera"));

  out = m_harness.run("translateScene", { { "x", 10.0 } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed);
  EXPECT_EQ(out.message, QStringLiteral("No camera"));
}

TEST_F(NavigatorCommandTest, rejectsUnknownOption)
{
  QVariantMap badRotate;
  badRotate.insert(QStringLiteral("extra"), 42);
  badRotate.insert(QStringLiteral("x"), 10.0);
  CommandOutcome out = m_harness.run("rotateScene", badRotate);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);

  QVariantMap badZoom;
  badZoom.insert(QStringLiteral("extra"), 42);
  badZoom.insert(QStringLiteral("delta"), 5.0);
  out = m_harness.run("zoomScene", badZoom);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);

  QVariantMap badTranslate;
  badTranslate.insert(QStringLiteral("extra"), 42);
  badTranslate.insert(QStringLiteral("x"), 10.0);
  out = m_harness.run("translateScene", badTranslate);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
}

TEST_F(NavigatorCommandTest, rotateSceneMissingAnglesFails)
{
  const CommandOutcome out = m_harness.run("rotateScene");
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed);
  EXPECT_TRUE(
    out.message.contains(QStringLiteral("At least one rotation angle")));
}

TEST_F(NavigatorCommandTest, rotateSceneExecutes)
{
  const MoleculeSnapshot beforeMol = m_harness.snapshot();
  const auto beforeView = m_renderer.camera().modelView();

  const CommandOutcome out =
    m_harness.run("rotateScene", { { "x", 25.0 }, { "y", 35.0 } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);

  // Molecule remains unchanged
  EXPECT_EQ(m_harness.snapshot().differences(beforeMol), QStringList());

  // Camera modelView matrix changed
  EXPECT_FALSE(m_renderer.camera().modelView().isApprox(beforeView));
}

TEST_F(NavigatorCommandTest, zoomSceneMissingDeltaFails)
{
  const CommandOutcome out = m_harness.run("zoomScene");
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed);
}

TEST_F(NavigatorCommandTest, zoomSceneExecutes)
{
  const MoleculeSnapshot beforeMol = m_harness.snapshot();
  const auto beforeView = m_renderer.camera().modelView();

  const CommandOutcome out = m_harness.run("zoomScene", { { "delta", 5.0 } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);

  // Molecule remains unchanged
  EXPECT_EQ(m_harness.snapshot().differences(beforeMol), QStringList());

  // Camera modelView matrix changed
  EXPECT_FALSE(m_renderer.camera().modelView().isApprox(beforeView));
}

TEST_F(NavigatorCommandTest, translateSceneMissingOffsetsFails)
{
  const CommandOutcome out = m_harness.run("translateScene");
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed);
  EXPECT_TRUE(
    out.message.contains(QStringLiteral("At least one translation offset")));
}

TEST_F(NavigatorCommandTest, translateSceneExecutes)
{
  const MoleculeSnapshot beforeMol = m_harness.snapshot();
  const auto beforeView = m_renderer.camera().modelView();

  const CommandOutcome out =
    m_harness.run("translateScene", { { "x", 15.0 }, { "y", -10.0 } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);

  // Molecule remains unchanged
  EXPECT_EQ(m_harness.snapshot().differences(beforeMol), QStringList());

  // Camera modelView matrix changed
  EXPECT_FALSE(m_renderer.camera().modelView().isApprox(beforeView));
}
