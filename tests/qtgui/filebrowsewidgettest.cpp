/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "qtguitests.h"
#include <gtest/gtest.h>

#include <avogadro/qtgui/filebrowsewidget.h>

#include <QtTest/QSignalSpy>

#include <QtWidgets/QApplication>
#include <QtWidgets/QLineEdit>

#include <QtCore/QVariant>

using Avogadro::QtGui::FileBrowseWidget;

// Need a QApplication to instantiate widget
#define START_QAPP                                                             \
  int argc = 1;                                                                \
  char argName[] = "FakeApp.exe";                                              \
  char* argv[2] = { argName, nullptr };                                        \
  QApplication app(argc, argv);                                                \
  Q_UNUSED(app)

TEST(FileBrowseWidgetTest, setFileName)
{
  START_QAPP;

  FileBrowseWidget widget;
  if (QT_VERSION == 6)
    QSignalSpy spy(&widget, &FileBrowseWidget::fileNameChanged);
  else
    QSignalSpy spy(&widget, SIGNAL(fileNameChanged(QString)));
  widget.setFileName("some file");
  EXPECT_EQ(1, spy.count());
  EXPECT_STREQ("some file", qPrintable(spy.front().front().toString()));
  EXPECT_STREQ("some file", qPrintable(widget.fileName()));
  EXPECT_STREQ("some file", qPrintable(widget.lineEdit()->text()));
}

TEST(FileBrowseWidgetTest, validExistingFile)
{
  START_QAPP;

  FileBrowseWidget widget;

  widget.setMode(FileBrowseWidget::ExistingFile);
  widget.setFileName(AVOGADRO_DATA "/data/ethane.cml");
  EXPECT_TRUE(widget.validFileName());
  widget.setFileName(AVOGADRO_DATA "/data/nonexisting.file");
  EXPECT_FALSE(widget.validFileName());
}

TEST(FileBrowseWidgetTest, validExecutableFile)
{
  START_QAPP;

  FileBrowseWidget widget;

  widget.setMode(FileBrowseWidget::ExecutableFile);
#ifndef Q_OS_WIN32 // Qt doesn't identify python files as exec on windows:
  widget.setFileName(AVOGADRO_DATA
                     "/tests/avogadro/scripts/inputgeneratortest.py");
#else  // Q_OS_WIN32
  widget.setFileName("C:/Windows/System32/cmd.exe");
#endif // Q_OS_WIN32
  EXPECT_TRUE(widget.validFileName());
  widget.setFileName(AVOGADRO_DATA "/data/ethane.cml");
  EXPECT_FALSE(widget.validFileName());
  widget.setFileName(AVOGADRO_DATA "/data/nonexisting.file");
  EXPECT_FALSE(widget.validFileName());
}
