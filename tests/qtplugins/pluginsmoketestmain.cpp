/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QByteArray>
#include <QtCore/QSettings>
#include <QtCore/QStandardPaths>
#include <QtCore/QTemporaryDir>
#include <QtWidgets/QApplication>

#include <gtest/gtest.h>

// One QApplication for the whole binary, created before any test runs. Unlike
// AvogadroQtPluginsTests, which links individual plugins, this binary links
// the shared plugin library and finds plugins through the PluginManager.
int main(int argc, char** argv)
{
  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
    qputenv("QT_QPA_PLATFORM", "offscreen");

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

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
