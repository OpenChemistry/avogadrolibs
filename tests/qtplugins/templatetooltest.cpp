/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "templatetool.h"

#include <QtGui/QKeyEvent>
#include <QtWidgets/QTabWidget>

#include <gtest/gtest.h>

using Avogadro::QtPlugins::TemplateTool;

namespace {

class TemplateToolCommandTest : public ::testing::Test
{
protected:
  int currentTab()
  {
    auto* tabs = m_tool.toolWidget()->findChild<QTabWidget*>();
    return tabs ? tabs->currentIndex() : -1;
  }

  // Send a key press through the tool, returning whether it was accepted.
  bool press(int key, Qt::KeyboardModifiers mods = Qt::NoModifier,
             const QString& text = QString())
  {
    QKeyEvent event(QEvent::KeyPress, key, mods, text);
    event.ignore();
    m_tool.keyPressEvent(&event);
    return event.isAccepted();
  }

  TemplateTool m_tool;
};

} // namespace

TEST_F(TemplateToolCommandTest, arrowKeysSwitchTabs)
{
  ASSERT_EQ(currentTab(), 0);
  EXPECT_TRUE(press(Qt::Key_Right));
  EXPECT_EQ(currentTab(), 1);
  EXPECT_TRUE(press(Qt::Key_Left));
  EXPECT_EQ(currentTab(), 0);
}

TEST_F(TemplateToolCommandTest, bracketKeysSwitchTabs)
{
  EXPECT_TRUE(press(Qt::Key_BracketRight, Qt::NoModifier, "]"));
  EXPECT_EQ(currentTab(), 1);
  EXPECT_TRUE(press(Qt::Key_BracketLeft, Qt::NoModifier, "["));
  EXPECT_EQ(currentTab(), 0);
}

TEST_F(TemplateToolCommandTest, navigationModifiersLeaveArrowsAlone)
{
  // Ctrl/Alt/Meta + arrows are camera navigation: not accepted, no tab change.
  for (auto mods : { Qt::ControlModifier, Qt::AltModifier, Qt::MetaModifier }) {
    EXPECT_FALSE(press(Qt::Key_Right, mods));
    EXPECT_EQ(currentTab(), 0);
  }
}
