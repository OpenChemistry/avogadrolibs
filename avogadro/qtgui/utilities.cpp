/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "utilities.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QProcessEnvironment>
#include <QtCore/QStringList>
#include <QtCore/QVersionNumber>

#include <algorithm>

namespace Avogadro::QtGui::Utilities {

namespace {

// Open Babel installs its data and plugins into a versioned directory, e.g.
// "share/openbabel/3.2.0". An install tree that has been reused across Open
// Babel updates can hold several of these, so take the highest version rather
// than giving up. Returns an empty string if there are no versioned
// directories under @a base.
QString highestVersionedDirectory(const QString& base)
{
  const QDir dir(base);
  QStringList filters;
  filters << "3.*"
          << "2.*";

  QString newest;
  QVersionNumber newestVersion;
  for (const QString& candidate : dir.entryList(filters, QDir::Dirs)) {
    // Only accept names that are entirely a version number, so that leftovers
    // such as "3.1.1-backup" are skipped rather than parsed as "3.1.1".
    const bool versionOnly =
      std::all_of(candidate.cbegin(), candidate.cend(),
                  [](QChar c) { return c.isDigit() || c == QLatin1Char('.'); });
    if (!versionOnly)
      continue;

    // Compare numerically, so that 3.10.0 sorts above 3.2.0.
    const QVersionNumber version = QVersionNumber::fromString(candidate);
    if (newest.isEmpty() || newestVersion < version) {
      newest = candidate;
      newestVersion = version;
    }
  }

  if (newest.isEmpty())
    return QString();

  return QDir::cleanPath(dir.absoluteFilePath(newest));
}

} // namespace

QString libraryDirectory()
{
  return QString(AvogadroLibs_LIB_DIR);
}

QString dataDirectory()
{
  return QString(AvogadroLibs_DATA_DIR);
}

QString openBabelDataDirectory()
{
#ifdef Q_OS_WIN32
  const QString dataDir =
    QDir::cleanPath(QCoreApplication::applicationDirPath() + "/data");
  // Callers treat an empty string as "not found", so don't hand back a path
  // that isn't there.
  return QDir(dataDir).exists() ? dataDir : QString();
#else
  return highestVersionedDirectory(QCoreApplication::applicationDirPath() +
                                   "/../share/openbabel");
#endif
}

QString openBabelLibraryDirectory()
{
#ifdef Q_OS_WIN32
  // The plugins are linked into the Open Babel library on Windows.
  return QString();
#else
  const QString base =
    QCoreApplication::applicationDirPath() + "/../lib/openbabel";
  const QString versioned = highestVersionedDirectory(base);
  if (!versioned.isEmpty())
    return versioned;

  // Some configurations install the plugins unversioned, directly into the
  // base directory. Only fall back to it if it actually exists.
  const QDir baseDir(base);
  return baseDir.exists() ? QDir::cleanPath(base) : QString();
#endif
}

QString findExecutablePath(QString program)
{
  // we want to return the path to a program if it exists
  // using the PATH system environment variable
  QProcessEnvironment system = QProcessEnvironment::systemEnvironment();
  QString path = system.value("PATH");
#ifdef Q_OS_WIN32
  QStringList paths = path.split(';');
#else
  QStringList paths = path.split(':');
  // check standard locations first
  paths.prepend("/usr/bin");
  paths.prepend("/usr/local/bin");
#endif

  // check the current application directory too
  paths.prepend(QCoreApplication::applicationDirPath());
  // and check "../bin" too
  paths.prepend(QCoreApplication::applicationDirPath() + "/../bin");

  // check to see if we find the program in that path
  for (const auto& dir : paths) {
    QFileInfo test(dir + '/' + program);
    if (test.isExecutable()) {
      // must exist to be executable, so we're done
      return dir;
    }
  }

  return QString();
}

QStringList findExecutablePaths(QStringList programs)
{
  QStringList result;

  // we want to return the path to a program if it exists
  // using the PATH system environment variable
  QProcessEnvironment system = QProcessEnvironment::systemEnvironment();
  QString path = system.value("PATH");
#ifdef Q_OS_WIN32
  QStringList paths = path.split(';');
#else
  QStringList paths = path.split(':');
  // check standard locations first
  paths.prepend("/usr/bin");
  paths.prepend("/usr/local/bin");
#endif

  // check the current application directory too
  paths.prepend(QCoreApplication::applicationDirPath());

  // loop through all programs and all possible paths
  for (const auto& program : programs) {
    for (const auto& dir : paths) {
      QFileInfo test(dir + '/' + program);
      if (test.isExecutable() && !result.contains(test.absoluteFilePath())) {
        // must exist to be executable, so add it to the list
        result << test.absoluteFilePath();
      }
    }
  }

  return result;
}

} // namespace Avogadro::QtGui::Utilities
