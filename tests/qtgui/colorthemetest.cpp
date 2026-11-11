/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/colortheme.h>

#include <QtGui/QColor>
#include <QtGui/QPalette>

#include <QtCore/QString>

using Avogadro::QtGui::ColorTheme;
using Avogadro::QtGui::colorTheme;
using Avogadro::QtGui::highlightColor;

TEST(ColorThemeTest, lightPalette)
{
  QPalette palette;
  palette.setColor(QPalette::Window, QColor(240, 240, 240));
  palette.setColor(QPalette::WindowText, QColor(10, 10, 10));
  EXPECT_EQ(colorTheme(palette), ColorTheme::Light);
}

TEST(ColorThemeTest, darkPalette)
{
  QPalette palette;
  palette.setColor(QPalette::Window, QColor(30, 30, 30));
  palette.setColor(QPalette::WindowText, QColor(230, 230, 230));
  EXPECT_EQ(colorTheme(palette), ColorTheme::Dark);
}

TEST(ColorThemeTest, equalLightnessIsLight)
{
  QPalette palette;
  palette.setColor(QPalette::Window, QColor(128, 128, 128));
  palette.setColor(QPalette::WindowText, QColor(128, 128, 128));
  EXPECT_EQ(colorTheme(palette), ColorTheme::Light);
}

TEST(ColorThemeTest, currentThemeIsCallable)
{
  // Platform-dependent: only check that it returns a valid value.
  const ColorTheme theme = colorTheme();
  EXPECT_TRUE(theme == ColorTheme::Light || theme == ColorTheme::Dark);
}

TEST(ColorThemeTest, highlightColorsDifferByTheme)
{
  for (const char* name :
       { "red", "green", "cyan", "blue", "purple", "pink", "white", "gray" }) {
    EXPECT_NE(highlightColor(name, ColorTheme::Light),
              highlightColor(name, ColorTheme::Dark))
      << name;
  }
  // These are identical in both tables.
  EXPECT_EQ(highlightColor("orange", ColorTheme::Light),
            highlightColor("orange", ColorTheme::Dark));
  EXPECT_EQ(highlightColor("yellow", ColorTheme::Light),
            highlightColor("yellow", ColorTheme::Dark));
}

TEST(ColorThemeTest, highlightColorValues)
{
  EXPECT_EQ(highlightColor("red", ColorTheme::Dark), QColor("#DC143C"));
  EXPECT_EQ(highlightColor("red", ColorTheme::Light), QColor("#800000"));
  EXPECT_EQ(highlightColor("white", ColorTheme::Dark), QColor("#F5F5F5"));
  EXPECT_EQ(highlightColor("white", ColorTheme::Light), QColor("#000000"));
  EXPECT_EQ(highlightColor("green", ColorTheme::Light), QColor("#32CD32"));
}

TEST(ColorThemeTest, unknownNameFallsBackToWhite)
{
  for (ColorTheme theme : { ColorTheme::Light, ColorTheme::Dark }) {
    EXPECT_EQ(highlightColor("not-a-color", theme),
              highlightColor("white", theme));
    EXPECT_EQ(highlightColor("", theme), highlightColor("white", theme));
  }
}
