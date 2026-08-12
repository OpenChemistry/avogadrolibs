/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/pythonscript.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QFile>
#include <QtCore/QJsonObject>
#include <QtCore/QTemporaryDir>
#include <QtTest/QSignalSpy>

using Avogadro::QtGui::PythonScript;

namespace {

// Ensure a QCoreApplication exists (required to run an event loop while the
// script executes). The test binary uses gtest_main, which does not create one.
QCoreApplication* ensureApp()
{
  if (QCoreApplication::instance())
    return QCoreApplication::instance();
  static int argc = 1;
  static char name[] = "PythonScriptTest";
  static char* argv[] = { name, nullptr };
  static QCoreApplication app(argc, argv);
  return &app;
}

// Windows line endings would otherwise make byte comparisons brittle.
QByteArray withoutCarriageReturns(QByteArray data)
{
  data.replace('\r', "");
  return data;
}

} // namespace

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

TEST(PythonScriptTest, AsyncProgressScanning)
{
  ensureApp();

  QTemporaryDir temporaryDirectory;
  ASSERT_TRUE(temporaryDirectory.isValid());

  // Mimics a real command script: progress envelopes and plain output on
  // stdout, log noise on stderr, and a pretty-printed result at the end.
  QFile script(temporaryDirectory.filePath("progress.py"));
  ASSERT_TRUE(script.open(QIODevice::WriteOnly | QIODevice::Text));
  const QByteArray source(
    "import json, sys\n"
    "print(json.dumps({'avogadro': {'message': 'Step 1 of 3', 'value': 1,"
    " 'maximum': 3}}), flush=True)\n"
    "sys.stderr.write('DEBUG library noise\\n')\n"
    "print('plain output', flush=True)\n"
    "print(json.dumps({'avogadro': {'message': 'Finishing'}}), flush=True)\n"
    "print(json.dumps({'result': 42, 'avogadro': 'not an envelope'},"
    " indent=2))\n");
  ASSERT_EQ(script.write(source), source.size());
  script.close();

  PythonScript pythonScript(script.fileName());
  pythonScript.setProgressScanning(true);
  QSignalSpy progressSpy(&pythonScript, &PythonScript::asyncProgress);
  QSignalSpy finishedSpy(&pythonScript, &PythonScript::finished);

  ASSERT_TRUE(pythonScript.asyncExecute({}, QByteArray(),
                                        /* mergedChannels = */ false));
  ASSERT_TRUE(finishedSpy.wait(30000));

  ASSERT_EQ(progressSpy.count(), 2);
  const auto first = progressSpy.at(0).at(0).value<QJsonObject>();
  EXPECT_EQ(first.value("message").toString(), QString("Step 1 of 3"));
  EXPECT_EQ(first.value("value").toInt(-1), 1);
  EXPECT_EQ(first.value("maximum").toInt(-1), 3);
  const auto second = progressSpy.at(1).at(0).value<QJsonObject>();
  EXPECT_EQ(second.value("message").toString(), QString("Finishing"));
  EXPECT_EQ(second.value("value").toInt(-1), -1);

  // Envelopes are gone; everything else survives, including the multi-line
  // result and its top-level "avogadro" member.
  EXPECT_EQ(withoutCarriageReturns(pythonScript.asyncResponse()),
            QByteArray("plain output\n{\n  \"result\": 42,\n"
                       "  \"avogadro\": \"not an envelope\"\n}\n"));

  // stderr is captured separately rather than corrupting the result.
  EXPECT_TRUE(
    pythonScript.asyncStandardError().contains("DEBUG library noise"));
}
