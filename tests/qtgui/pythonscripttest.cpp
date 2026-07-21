/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/pythonscript.h>

#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>

using Avogadro::QtGui::PythonScript;

TEST(PythonScriptTest, WindowsUsesUtf8Mode)
{
#ifndef Q_OS_WIN
  GTEST_SKIP() << "PYTHONUTF8 is only set on Windows.";
#else
  QTemporaryDir temporaryDirectory;
  ASSERT_TRUE(temporaryDirectory.isValid());

  QFile script(temporaryDirectory.filePath("utf8_mode.py"));
  ASSERT_TRUE(script.open(QIODevice::WriteOnly | QIODevice::Text));
  const QByteArray source("import sys\nprint(sys.flags.utf8_mode)\n");
  ASSERT_EQ(script.write(source), source.size());
  script.close();

  PythonScript pythonScript(script.fileName());
  EXPECT_EQ(pythonScript.execute({}).trimmed(), QByteArray("1"));
#endif
}
