/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "editor.h"
#include "editortoolwidget.h"

#include <avogadro/qtgui/periodictableview.h>

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QSettings>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <gtest/gtest.h>

#include <array>
#include <string>

using Avogadro::QtPlugins::Editor;
using Avogadro::QtPlugins::EditorToolWidget;

class EditorTest : public testing::Test
{
protected:
  void SetUp() override
  {
    static int argc = 1;
    static std::string name = "editortest";
    static std::array<char*, 2> argv{ name.data(), nullptr };
    static QApplication app(argc, argv.data());
    static QTemporaryDir settings;
    QCoreApplication::setOrganizationName("AvogadroTests");
    QCoreApplication::setApplicationName("Editor");
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
                       settings.path());
    QSettings().clear();
  }
};

TEST_F(EditorTest, OptionsSurvivePanelCreationAndDestruction)
{
  Editor editor;
  ASSERT_TRUE(
    editor.handleCommand("setDrawOptions", { { "atomicNumber", 26 },
                                             { "bondOrder", 2 },
                                             { "adjustHydrogens", false } }));
  auto* panel = qobject_cast<EditorToolWidget*>(editor.toolWidget());
  ASSERT_NE(panel, nullptr);
  EXPECT_EQ(panel->atomicNumber(), 26);
  EXPECT_EQ(panel->bondOrder(), 2);
  EXPECT_FALSE(panel->adjustHydrogens());
  delete panel;
  editor.setAtomicNumber(8);
  panel = qobject_cast<EditorToolWidget*>(editor.toolWidget());
  ASSERT_NE(panel, nullptr);
  EXPECT_EQ(panel->atomicNumber(), 8);
  EXPECT_EQ(panel->bondOrder(), 2);
  EXPECT_FALSE(panel->adjustHydrogens());
}

TEST_F(EditorTest, WidgetAndCommandsSynchronizeOnce)
{
  Editor editor;
  auto* panel = qobject_cast<EditorToolWidget*>(editor.toolWidget());
  QSignalSpy changes(&editor, &Editor::drawOptionsChanged);
  QSignalSpy widgetChanges(panel, &EditorToolWidget::optionsChanged);
  editor.setAtomicNumber(26);
  EXPECT_EQ(panel->atomicNumber(), 26);
  EXPECT_EQ(changes.count(), 1);
  EXPECT_EQ(widgetChanges.count(), 0);
  auto* elements = panel->findChild<QComboBox*>("element");
  ASSERT_NE(elements, nullptr);
  elements->setCurrentIndex(elements->findData(8));
  EXPECT_EQ(editor.atomicNumber(), 8);
  EXPECT_EQ(changes.count(), 2);
  EXPECT_EQ(widgetChanges.count(), 1);
  panel->findChild<QComboBox*>("bondOrder")->setCurrentIndex(3);
  panel->findChild<QCheckBox*>("adjustHydrogens")->setChecked(false);
  EXPECT_EQ(editor.bondOrder(), 3);
  EXPECT_FALSE(editor.adjustHydrogens());
  EXPECT_EQ(changes.count(), 4);
  EXPECT_FALSE(
    editor.handleCommand("setDrawOptions", { { "atomicNumber", 255 } }));
  EXPECT_EQ(editor.atomicNumber(), 8);
  EXPECT_EQ(changes.count(), 4);
}

TEST_F(EditorTest, PeriodicTableDoesNotPublishSentinelsOrIntermediateElements)
{
  Editor editor;
  auto* panel = qobject_cast<EditorToolWidget*>(editor.toolWidget());
  auto* elements = panel->findChild<QComboBox*>("element");
  QSignalSpy changes(panel, &EditorToolWidget::optionsChanged);
  elements->setCurrentIndex(elements->findData(255));
  EXPECT_EQ(panel->atomicNumber(), 6);
  EXPECT_EQ(editor.atomicNumber(), 6);
  EXPECT_EQ(changes.count(), 0);
  auto* table = panel->findChild<Avogadro::QtGui::PeriodicTableView*>();
  ASSERT_NE(table, nullptr);
  ASSERT_TRUE(
    QMetaObject::invokeMethod(table, "elementChanged", Q_ARG(int, 26)));
  EXPECT_EQ(panel->atomicNumber(), 26);
  EXPECT_EQ(editor.atomicNumber(), 26);
  EXPECT_EQ(changes.count(), 1);
  EXPECT_EQ(elements->findData(255), elements->count() - 1);
}
