/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QByteArray>
#include <QtWidgets/QApplication>

#include <gtest/gtest.h>

// One QApplication for the whole binary, created before any test runs.
// Plugins build QActions (and some build widgets) in their constructors, so a
// QCoreApplication is not enough; and a per-file ensureApp() as in
// tests/qtgui would let the first test file decide which kind everyone gets.
int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);

  // CTest sets this too; default it for anyone running the binary by hand.
  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
    qputenv("QT_QPA_PLATFORM", "offscreen");

  QApplication app(argc, argv);
  QCoreApplication::setOrganizationName("OpenChemistry");
  QCoreApplication::setApplicationName("AvogadroQtPluginsTests");

  return RUN_ALL_TESTS();
}
