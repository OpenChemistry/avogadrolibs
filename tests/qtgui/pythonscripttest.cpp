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

namespace {
// Run @p source asynchronously with progress scanning (as InterfaceScript
// does) and wait for it to finish.
void runAsyncScript(PythonScript& pythonScript, const QString& path,
                    const QByteArray& source)
{
  QFile script(path);
  ASSERT_TRUE(script.open(QIODevice::WriteOnly | QIODevice::Text));
  ASSERT_EQ(script.write(source), source.size());
  script.close();

  pythonScript.setProgressScanning(true);
  QSignalSpy finishedSpy(&pythonScript, &PythonScript::finished);
  ASSERT_TRUE(pythonScript.asyncExecute({}, QByteArray(),
                                        /* mergedChannels = */ false));
  ASSERT_TRUE(finishedSpy.wait(30000));
}
} // namespace

// A failing script must leave an explanation in errorList(), which is all that
// the command dialog looks at; stderr chatter from a successful one must not.
TEST(PythonScriptTest, AsyncNonZeroExitRecordsError)
{
  ensureApp();
  QTemporaryDir temporaryDirectory;
  ASSERT_TRUE(temporaryDirectory.isValid());

  PythonScript failing(temporaryDirectory.filePath("fail.py"));
  runAsyncScript(failing, temporaryDirectory.filePath("fail.py"),
                 "import sys\n"
                 "sys.stderr.write('ModuleNotFoundError: no module xyz\\n')\n"
                 "sys.exit(3)\n");
  ASSERT_TRUE(failing.hasErrors());
  const QString errors = failing.errorList().join("\n");
  EXPECT_TRUE(errors.contains("error code 3")) << qPrintable(errors);
  EXPECT_TRUE(errors.contains("ModuleNotFoundError")) << qPrintable(errors);
}

TEST(PythonScriptTest, AsyncSuccessWithStderrNoiseRecordsNoError)
{
  ensureApp();
  QTemporaryDir temporaryDirectory;
  ASSERT_TRUE(temporaryDirectory.isValid());

  PythonScript noisy(temporaryDirectory.filePath("noisy.py"));
  runAsyncScript(noisy, temporaryDirectory.filePath("noisy.py"),
                 "import sys\n"
                 "sys.stderr.write('DeprecationWarning: harmless\\n')\n"
                 "print('{}')\n");
  EXPECT_FALSE(noisy.hasErrors());
}

#ifndef Q_OS_WIN
TEST(PythonScriptTest, AsyncCrashRecordsError)
{
  ensureApp();
  QTemporaryDir temporaryDirectory;
  ASSERT_TRUE(temporaryDirectory.isValid());

  PythonScript crashing(temporaryDirectory.filePath("crash.py"));
  runAsyncScript(crashing, temporaryDirectory.filePath("crash.py"),
                 "import os, signal\n"
                 "os.kill(os.getpid(), signal.SIGKILL)\n");
  ASSERT_TRUE(crashing.hasErrors());
  EXPECT_TRUE(crashing.errorList().join("\n").contains("crashed"));
}
#endif

// Scripts must be able to tell whether Avogadro is listening: releases up to
// 2.0.0 cannot parse output containing progress envelopes.
TEST(PythonScriptTest, AdvertisesProgressProtocol)
{
  QTemporaryDir temporaryDirectory;
  ASSERT_TRUE(temporaryDirectory.isValid());

  QFile script(temporaryDirectory.filePath("environment.py"));
  ASSERT_TRUE(script.open(QIODevice::WriteOnly | QIODevice::Text));
  const QByteArray source(
    "import os\nprint(os.environ.get('AVO_PROGRESS_PROTOCOL', 'unset'))\n");
  ASSERT_EQ(script.write(source), source.size());
  script.close();

  // Not scanning: the variable must be absent, or a script would print
  // envelopes that nothing is there to strip out.
  PythonScript quiet(script.fileName());
  EXPECT_EQ(quiet.execute({}).trimmed(), QByteArray("unset"));

  PythonScript scanning(script.fileName());
  scanning.setProgressScanning(true);
  EXPECT_EQ(scanning.execute({}).trimmed(), QByteArray("1"));
}
