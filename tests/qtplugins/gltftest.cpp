/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "gltf.h"

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/scene.h>

#include <gtest/gtest.h>

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>

using Avogadro::QtPlugins::GLTF;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::Rendering::Camera;
using Avogadro::Rendering::Scene;

// The export command exports the scene, which is a plain object here (no GL
// context), so the harness hands the plugin its own.
namespace {

class GltfCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildMethanol();
    m_harness.attach(&m_gltf);
    m_gltf.setCamera(&m_camera);
    m_gltf.setScene(&m_scene);
    m_harness.registerCommands();
  }

  Camera m_camera;
  Scene m_scene;
  GLTF m_gltf;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(GltfCommandTest, registersDocumentedCommands)
{
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  EXPECT_EQ(registered.keys(), QStringList({ "exportGltf" }));
}

TEST_F(GltfCommandTest, exportsWithoutAskingAnything)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());
  for (const char* colors : { "split", "gradient" }) {
    const QString path = dir.filePath(QString("%1.glb").arg(colors));
    const CommandOutcome out = m_harness.run(
      "exportGltf", { { "fileName", path }, { "bondColors", colors } });
    EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
    EXPECT_FALSE(out.async);
    EXPECT_TRUE(out.clean()) << describe(out);
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::ReadOnly));
    EXPECT_EQ(file.read(4), QByteArray("glTF"));
  }
}

TEST_F(GltfCommandTest, rejectsBadOptions)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());
  const QString path = dir.filePath("bad.glb");
  EXPECT_EQ(m_harness.run("exportGltf", {}).status, CommandStatus::Failed);
  EXPECT_EQ(
    m_harness
      .run("exportGltf", { { "fileName", path }, { "bondColors", "rainbow" } })
      .status,
    CommandStatus::Failed);
  EXPECT_FALSE(QFile::exists(path));
}

TEST_F(GltfCommandTest, failureLeavesExistingFileAlone)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());
  // A directory that does not exist cannot be written to.
  const CommandOutcome out = m_harness.run(
    "exportGltf", { { "fileName", dir.filePath("missing/out.glb") } });
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_FALSE(QDir(dir.path()).exists("missing"));
}
