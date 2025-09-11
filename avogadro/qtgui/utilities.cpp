/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "utilities.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QFileInfo>
#include <QtCore/QProcessEnvironment>
#include <QtCore/QStringList>

namespace Avogadro::QtGui::Utilities {

QString libraryDirectory()
{
  return QString(AvogadroLibs_LIB_DIR);
}

QString dataDirectory()
{
  return QString(AvogadroLibs_DATA_DIR);
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
