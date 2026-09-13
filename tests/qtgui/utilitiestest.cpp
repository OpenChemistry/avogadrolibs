/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/utilities.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QTemporaryDir>

using Avogadro::QtGui::Utilities::findExecutablePath;

namespace {

// Ensure a QCoreApplication exists (findExecutablePath() searches
// applicationDirPath(), which warns and returns an empty string without one,
// turning the first search entries into root-relative paths).
// The test binary uses gtest_main which does not create one.
QCoreApplication* ensureApp()
{
  if (QCoreApplication::instance())
    return QCoreApplication::instance();
  static int argc = 1;
  static char name[] = "UtilitiesTest";
  static char* argv[] = { name, nullptr };
  static QCoreApplication app(argc, argv);
  return &app;
}

// A name no real installation can supply, so that a pixi (or anything else)
// genuinely present on the test machine cannot decide the result.
#ifdef Q_OS_WIN
const char* fakeProgram = "avogadro-test-pixi.exe";
const char* pathSeparator = ";";
#else
const char* fakeProgram = "avogadro-test-pixi";
const char* pathSeparator = ":";
#endif

// Create an executable stand-in for a program at @a dir/@a name.
bool createExecutable(const QString& dir, const QString& name)
{
  if (!QDir().mkpath(dir))
    return false;

  const QString path = dir + '/' + name;
  QFile file(path);
  if (!file.open(QIODevice::WriteOnly))
    return false;
  file.write("#!/bin/sh\n");
  file.close();

  return QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner |
                                       QFile::ExeOwner);
}

// Save and restore the environment variables these tests scribble on, so the
// order in which gtest runs them cannot matter.
class ScopedEnvironment
{
public:
  ScopedEnvironment()
    : m_path(qgetenv("PATH")), m_pixiHome(qgetenv("PIXI_HOME"))
  {
  }

  ~ScopedEnvironment()
  {
    qputenv("PATH", m_path);
    if (m_pixiHome.isEmpty())
      qunsetenv("PIXI_HOME");
    else
      qputenv("PIXI_HOME", m_pixiHome);
  }

private:
  QByteArray m_path;
  QByteArray m_pixiHome;
};

} // namespace

// pixi installs into $PIXI_HOME/bin (default $HOME/.pixi/bin) and puts that
// directory on PATH from the shell profile. Avogadro started from a desktop
// launcher, the Dock or Finder never sees that profile, so the directory has
// to be searched explicitly or pixi looks uninstalled.
TEST(UtilitiesTest, findsPixiInPixiHomeWhenNotOnPath)
{
  ensureApp();
  ScopedEnvironment restoreEnvironment;

  QTemporaryDir tmp;
  ASSERT_TRUE(tmp.isValid());

  const QString binDir = tmp.path() + "/bin";
  ASSERT_TRUE(createExecutable(binDir, fakeProgram));

  qputenv("PIXI_HOME", tmp.path().toUtf8());
  qputenv("PATH", QByteArray());

  EXPECT_EQ(QDir(findExecutablePath(fakeProgram)).absolutePath(),
            QDir(binDir).absolutePath());
}

// A pixi the user has deliberately put on PATH must still win.
TEST(UtilitiesTest, pathTakesPrecedenceOverPixiHome)
{
  ensureApp();
  ScopedEnvironment restoreEnvironment;

  QTemporaryDir tmp;
  ASSERT_TRUE(tmp.isValid());

  const QString pixiHomeBin = tmp.path() + "/pixi-home/bin";
  const QString pathBin = tmp.path() + "/on-path";
  ASSERT_TRUE(createExecutable(pixiHomeBin, fakeProgram));
  ASSERT_TRUE(createExecutable(pathBin, fakeProgram));

  qputenv("PIXI_HOME", (tmp.path() + "/pixi-home").toUtf8());
  qputenv("PATH", pathBin.toUtf8());

  EXPECT_EQ(QDir(findExecutablePath(fakeProgram)).absolutePath(),
            QDir(pathBin).absolutePath());
}

TEST(UtilitiesTest, missingProgramReturnsEmptyPath)
{
  ensureApp();
  ScopedEnvironment restoreEnvironment;

  QTemporaryDir tmp;
  ASSERT_TRUE(tmp.isValid());

  qputenv("PIXI_HOME", tmp.path().toUtf8());
  qputenv("PATH", QByteArray());

  EXPECT_TRUE(
    findExecutablePath("avogadro-no-such-program-should-exist").isEmpty());
}

// An empty PATH entry must not turn into a search of the filesystem root.
TEST(UtilitiesTest, emptyPathEntriesAreIgnored)
{
  ensureApp();
  ScopedEnvironment restoreEnvironment;

  QTemporaryDir tmp;
  ASSERT_TRUE(tmp.isValid());

  const QString binDir = tmp.path() + "/bin";
  ASSERT_TRUE(createExecutable(binDir, fakeProgram));

  qputenv("PIXI_HOME", tmp.path().toUtf8());
  qputenv("PATH", QByteArray(pathSeparator) + pathSeparator);

  EXPECT_EQ(QDir(findExecutablePath(fakeProgram)).absolutePath(),
            QDir(binDir).absolutePath());
}
