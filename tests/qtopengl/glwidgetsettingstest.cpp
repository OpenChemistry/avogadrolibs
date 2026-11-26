/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gltesthelpers.h"

#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/solidpipeline.h>

#include <gtest/gtest.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QSettings>
#include <QtCore/QTemporaryDir>

using Avogadro::QtOpenGL::GLWidget;

namespace {

// Points QSettings at a temporary INI directory under a throwaway
// organization, so nothing reaches the real preferences, and restores the
// previous state afterwards.
class GLWidgetSettingsTest : public testing::Test
{
protected:
  void SetUp() override
  {
    if (Avogadro::TestGL::ensureApp() == nullptr)
      GTEST_SKIP() << "A QApplication is required for QWidget tests.";
    ASSERT_TRUE(dir.isValid());
    oldOrg = QCoreApplication::organizationName();
    oldApp = QCoreApplication::applicationName();
    oldFormat = QSettings::defaultFormat();
    QCoreApplication::setOrganizationName("AvogadroLibsTestsOrg");
    QCoreApplication::setApplicationName("AvogadroGLWidgetSettingsTest");
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, dir.path());
    QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope,
                       dir.path());
    active = true;
    clearKeys();
  }

  void TearDown() override
  {
    if (!active)
      return;
    clearKeys();
    QSettings::setDefaultFormat(oldFormat);
    QCoreApplication::setOrganizationName(oldOrg);
    QCoreApplication::setApplicationName(oldApp);
  }

  static void clearKeys()
  {
    QSettings settings;
    settings.remove(GLWidget::antiAliasingSettingsKey);
    settings.remove(GLWidget::edgeSupersamplingSettingsKey);
    settings.sync();
  }

  QTemporaryDir dir;
  QString oldOrg, oldApp;
  QSettings::Format oldFormat = QSettings::NativeFormat;
  bool active = false;
};

} // namespace

TEST_F(GLWidgetSettingsTest, absentKeysKeepPipelineDefaults)
{
  const Avogadro::Rendering::SolidPipeline reference;
  GLWidget widget;
  const auto& pipeline = widget.renderer().solidPipeline();
  EXPECT_EQ(pipeline.antiAliasingEnabled(), reference.antiAliasingEnabled());
  EXPECT_EQ(pipeline.edgeSupersampling(), reference.edgeSupersampling());
}

TEST_F(GLWidgetSettingsTest, keysAreApplied)
{
  const Avogadro::Rendering::SolidPipeline reference;
  {
    QSettings settings;
    settings.setValue(GLWidget::antiAliasingSettingsKey,
                      !reference.antiAliasingEnabled());
    settings.setValue(GLWidget::edgeSupersamplingSettingsKey,
                      !reference.edgeSupersampling());
  }
  GLWidget widget;
  const auto& pipeline = widget.renderer().solidPipeline();
  EXPECT_EQ(pipeline.antiAliasingEnabled(), !reference.antiAliasingEnabled());
  EXPECT_EQ(pipeline.edgeSupersampling(), !reference.edgeSupersampling());
}

TEST_F(GLWidgetSettingsTest, keyStringsMatchTheApplication)
{
  EXPECT_STREQ(GLWidget::antiAliasingSettingsKey, "MainWindow/fxaa_enabled");
  EXPECT_STREQ(GLWidget::edgeSupersamplingSettingsKey,
               "MainWindow/ed_supersampling");
}
