/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>
#include "qtguitests.h"

#include <avogadro/qtgui/filebrowsewidget.h>

#include <QtTest/QSignalSpy>

#include <QtGui/QApplication>
#include <QtGui/QLineEdit>

#include <QtCore/QVariant>

using namespace Avogadro::QtGui;

// Need a QApplication to instantiate widget
#define START_QAPP \
  int argc = 1; \
  char argName[] = "FakeApp.exe"; \
  char *argv[2] = {argName, NULL}; \
  QApplication app(argc, argv); \
  Q_UNUSED(app)

TEST(FileBrowseWidgetTest, setFileName)
{
  START_QAPP;

  FileBrowseWidget widget;

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
  widget.setFileName(AVOGADRO_DATA "/data/inputgeneratortest.py");
  EXPECT_TRUE(widget.validFileName());
  widget.setFileName(AVOGADRO_DATA "/data/ethane.cml");
  EXPECT_FALSE(widget.validFileName());
  widget.setFileName(AVOGADRO_DATA "/data/nonexisting.file");
  EXPECT_FALSE(widget.validFileName());
}
