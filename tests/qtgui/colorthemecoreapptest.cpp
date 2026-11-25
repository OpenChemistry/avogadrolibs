/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/colortheme.h>

#include <QtCore/QCoreApplication>
#include <QtGui/QGuiApplication>
#include <QtGui/QPalette>

using Avogadro::QtGui::colorTheme;

TEST(ColorThemeCoreAppTest, coreApplicationOnly)
{
  // Regression: a plain QCoreApplication must not be used as a
  // QGuiApplication (this crashed in the sanitizer CI).
  ASSERT_NE(QCoreApplication::instance(), nullptr);
  ASSERT_EQ(qobject_cast<QGuiApplication*>(QCoreApplication::instance()),
            nullptr);

  EXPECT_EQ(colorTheme(), colorTheme(QPalette()));
}

// This binary has its own main(): the test above needs a QCoreApplication, and
// AvogadroQtGuiTests creates a QApplication for everything else.
int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  QCoreApplication app(argc, argv);
  return RUN_ALL_TESTS();
}
