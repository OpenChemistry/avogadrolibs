/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "plugintestutils.h"

#include <QtCore/QByteArray>
#include <QtCore/QSettings>
#include <QtCore/QStandardPaths>
#include <QtCore/QTemporaryDir>
#include <QtGui/QOffscreenSurface>
#include <QtGui/QOpenGLContext>
#include <QtWidgets/QApplication>

#include <gtest/gtest.h>

#include <iostream>

// One QApplication for the whole binary, created before any test runs. Unlike
// AvogadroQtPluginsTests, which links individual plugins, this binary links
// the shared plugin library and finds plugins through the PluginManager.
int main(int argc, char** argv)
{
  // macOS' offscreen platform has no OpenGL; its real one does, headless.
  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM")) {
#ifdef Q_OS_MACOS
    qputenv("QT_QPA_PLATFORM", "cocoa");
#else
    qputenv("QT_QPA_PLATFORM", "offscreen");
#endif
  }

  // Plugins read and write QSettings: keep the user's out, and keep each run
  // from seeing the last one's.
  QStandardPaths::setTestModeEnabled(true);
  QTemporaryDir settingsDir;
  QSettings::setDefaultFormat(QSettings::IniFormat);
  QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
                     settingsDir.path());

  QApplication app(argc, argv);
  QCoreApplication::setOrganizationName("OpenChemistry");
  QCoreApplication::setApplicationName("AvogadroQtPluginSmokeTests");

  // Text labels call OpenGL as they are built, which crashes with no current
  // context. Nothing here renders, so a context on an offscreen surface is all
  // that is needed; tests that need one skip themselves if there is none.
  QOffscreenSurface surface;
  surface.create();
  QOpenGLContext context;
  const bool haveContext =
    context.create() && surface.isValid() && context.makeCurrent(&surface);
  Avogadro::QtPluginsTests::setHaveGLContext(haveContext);
  if (!haveContext)
    std::cerr << "No OpenGL context: tests that need one will be skipped.\n";

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
