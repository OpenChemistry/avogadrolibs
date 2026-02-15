/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "pythonscript.h"

#include "avogadropython.h"
#include "utilities.h"

#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QLocale>
#include <QtCore/QProcess>
#include <QtCore/QSettings>
#include <QtCore/QStandardPaths>

namespace Avogadro::QtGui {

// Check whether the plugin directory has a usable pixi-managed python
static bool hasDefaultPixiManifest(const QString& pluginDir)
{
  if (!QDir(pluginDir + "/.pixi").exists())
    return false;

  QString pythonPath = "/.pixi/envs/default/bin/";
#ifdef Q_OS_WIN
  pythonPath += "python.exe";
#else
  pythonPath += "python";
#endif
  QFileInfo python(pluginDir + pythonPath);
  return python.exists() && python.isExecutable();
}

PythonScript::PythonScript(const QString& scriptFilePath_, QObject* parent_)
  : QObject(parent_), m_debug(!qgetenv("AVO_PYTHON_SCRIPT_DEBUG").isEmpty()),
    m_scriptFilePath(scriptFilePath_), m_process(nullptr)
{
  setDefaultPythonInterpreter();
}

PythonScript::PythonScript(QObject* parent_)
  : QObject(parent_), m_debug(!qgetenv("AVO_PYTHON_SCRIPT_DEBUG").isEmpty()),
    m_process(nullptr)
{
  setDefaultPythonInterpreter();
}

PythonScript::~PythonScript() {}

void PythonScript::setScriptFilePath(const QString& scriptFile)
{
  m_scriptFilePath = scriptFile;
  m_packageMode = false;
}

void PythonScript::setPackageInfo(const QString& packageDir,
                                  const QString& command,
                                  const QString& identifier)
{
  m_packageDir = packageDir;
  m_packageCommand = command;
  m_packageIdentifier = identifier;
  m_packageMode = true;
  m_scriptFilePath.clear();
}

void PythonScript::setDefaultPythonInterpreter()
{
  if (m_pythonInterpreter.isEmpty()) {
    m_pythonInterpreter =
      QSettings().value(QStringLiteral("interpreters/python")).toString();
  }
  if (m_pythonInterpreter.isEmpty())
    // compiled-in default
    m_pythonInterpreter = pythonInterpreterPath;

  // check to see if the interpreter exists and is executable
  QFileInfo info(m_pythonInterpreter);
  if (!info.isExecutable()) {
#ifndef NDEBUG
    qWarning() << "Python interpreter" << m_pythonInterpreter
               << "does not exist trying \"python\" in your path."
               << "Please set a path to the python interpreter.";
#endif

    // let's try to find a python
#ifdef Q_OS_WIN
    QString python("python.exe");
#else
    QString python("python3");
#endif

    QString path = Utilities::findExecutablePath(python);
    if (path.isEmpty()) {
      qWarning() << "Can't find python in your path";
    } else {
      // add a "/" to the end
      path.append('/');
    }
    m_pythonInterpreter = path + python;
  }

  // check if we have pixi
#ifdef Q_OS_WIN
  QString pixi("pixi.exe");
#else
  QString pixi("pixi");
#endif

  m_pixi = Utilities::findExecutablePath(pixi);
#ifndef NDEBUG
  if (m_pixi.isEmpty()) {
    qWarning() << "Can't find pixi in your path";
  }
#endif
}

QByteArray PythonScript::execute(const QStringList& args,
                                 const QByteArray& scriptStdin)
{
  clearErrors();
  QProcess proc;

  // Merge stdout and stderr
  proc.setProcessChannelMode(QProcess::MergedChannels);

  // Add debugging flag if needed.
  QStringList realArgs(args);
  if (m_debug)
    realArgs.prepend(QStringLiteral("--debug"));

  // Add the global language / locale to *all* calls
  realArgs.append("--lang");
  realArgs.append(QLocale().name());

  // --- Package mode: pixi run <command> <identifier> [args] ---
  if (m_packageMode) {
    if (m_pixi.isEmpty()) {
      m_errors << tr("Package mode requires pixi but it was not found.");
      return QByteArray();
    }

    // Build: pixi run <command> <identifier> [args]
    realArgs.prepend(m_packageIdentifier);
    realArgs.prepend(m_packageCommand);
    realArgs.prepend("--as-is");
    realArgs.prepend("run");

    proc.setWorkingDirectory(m_packageDir);

#ifdef Q_OS_WIN
    QString pixi(m_pixi + "/pixi.exe");
#else
    QString pixi(m_pixi + "/pixi");
#endif

    if (m_debug) {
      qDebug() << "Executing (package)" << pixi
               << realArgs.join(QStringLiteral(" ")) << "<" << scriptStdin;
      qDebug() << "Working directory is" << m_packageDir;
    }
    proc.start(pixi, realArgs);

  } else {
    // --- Script file mode ---
    realArgs.prepend(m_scriptFilePath);

    // Check if the user installed the default pixi manifest
    QString pluginDir =
      QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    bool defaultManifest = hasDefaultPixiManifest(pluginDir);

    if (defaultManifest && !m_pixi.isEmpty()) {
      // Prepend "python" for .py scripts so pixi knows the interpreter
      if (m_scriptFilePath.contains(".py"))
        realArgs.prepend("python");

      realArgs.prepend("--as-is");

      // Check if the script directory (or its parent) has a .pixi directory
      QString scriptDirPath(QFileInfo(m_scriptFilePath).absolutePath());
      bool hasPixiDir = QDir(scriptDirPath + "/.pixi").exists() ||
                        QDir(scriptDirPath + "/../.pixi").exists();

      // Use the default manifest if the script doesn't have its own .pixi
      // directory and isn't in the user plugin directory (i.e., we bundled it)
      if (!pluginDir.isEmpty() && !hasPixiDir &&
          !m_scriptFilePath.startsWith(pluginDir)) {
#ifndef NDEBUG
        qDebug() << "Using manifest in" << pluginDir;
#endif
        realArgs.prepend(pluginDir);
        realArgs.prepend("--manifest-path");
      } else if (hasPixiDir || m_scriptFilePath.startsWith(pluginDir)) {
        proc.setWorkingDirectory(scriptDirPath);
      } else {
        if (m_debug) {
          qDebug() << "No valid pixi manifest configuration found for"
                   << m_scriptFilePath;
        }
        return QByteArray();
      }

      realArgs.prepend("run");

#ifdef Q_OS_WIN
      QString pixi(m_pixi + "/pixi.exe");
#else
      QString pixi(m_pixi + "/pixi");
#endif

      if (m_debug) {
        qDebug() << "Executing" << pixi << realArgs.join(QStringLiteral(" "))
                 << "<" << scriptStdin;
        qDebug() << "Working directory is" << proc.workingDirectory();
      }
      proc.start(pixi, realArgs);
    } else {
      // Plain python
      if (m_debug) {
        qDebug() << "Executing" << m_pythonInterpreter
                 << realArgs.join(QStringLiteral(" ")) << "<" << scriptStdin;
      }
      proc.start(m_pythonInterpreter, realArgs);
    }
  } // end script-file mode

  // Write scriptStdin to the process's stdin
  if (!scriptStdin.isNull()) {
    if (!proc.waitForStarted(5000) && m_debug) {
      m_errors << tr("Error running script '%1 %2': Timed out waiting for "
                     "start (%3).")
                    .arg(m_pythonInterpreter,
                         realArgs.join(QStringLiteral(" ")),
                         processErrorString(proc));
      return QByteArray();
    }

    qint64 len = proc.write(scriptStdin);
    if (len != static_cast<qint64>(scriptStdin.size()) && m_debug) {
      m_errors << tr("Error running script '%1 %2': failed to write to stdin "
                     "(len=%3, wrote %4 bytes, QProcess error: %5).")
                    .arg(m_pythonInterpreter)
                    .arg(realArgs.join(QStringLiteral(" ")))
                    .arg(scriptStdin.size())
                    .arg(len)
                    .arg(processErrorString(proc));
      return QByteArray();
    }
    proc.closeWriteChannel();
  }

  if (!proc.waitForFinished(5000) && m_debug) {
    m_errors << tr("Error running script '%1 %2': Timed out waiting for "
                   "finish (%3).")
                  .arg(m_pythonInterpreter, realArgs.join(QStringLiteral(" ")),
                       processErrorString(proc));
    return QByteArray();
  }

  if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0) {
    if (m_debug)
      m_errors << tr("Error running script '%1 %2': Abnormal exit status %3 "
                     "(%4: %5)\n\nOutput:\n%6")
                    .arg(m_pythonInterpreter)
                    .arg(realArgs.join(QStringLiteral(" ")))
                    .arg(proc.exitCode())
                    .arg(processErrorString(proc))
                    .arg(proc.errorString())
                    .arg(QString(proc.readAll()));
    else
      m_errors << tr("Warning '%1'").arg(proc.errorString());
    return QByteArray();
  }

  QByteArray result(proc.readAll());

  if (m_debug) {
    qDebug() << "Output:" << result;
    qDebug() << " Errors: " << m_errors;
  }

  return result;
}

void PythonScript::asyncExecute(const QStringList& args,
                                const QByteArray& scriptStdin)
{
  clearErrors();
  if (m_process != nullptr) {
    // bad news
    m_process->terminate();
    disconnect(m_process, SIGNAL(finished()), this, SLOT(processsFinished()));
    m_process->deleteLater();
  }
  m_process = new QProcess(parent());

  // Merge stdout and stderr
  m_process->setProcessChannelMode(QProcess::MergedChannels);

  // Add debugging flag if needed.
  QStringList realArgs(args);
  if (m_debug)
    realArgs.prepend(QStringLiteral("--debug"));

  // Add the global language / locale to *all* calls
  realArgs.append("--lang");
  realArgs.append(QLocale().name());

  // --- Package mode: pixi run <command> <identifier> [args] ---
  if (m_packageMode) {
    if (m_pixi.isEmpty()) {
      m_errors << tr("Package mode requires pixi but it was not found.");
      return;
    }

    realArgs.prepend(m_packageIdentifier);
    realArgs.prepend(m_packageCommand);
    realArgs.prepend("--as-is");
    realArgs.prepend("run");

    m_process->setWorkingDirectory(m_packageDir);

#ifdef Q_OS_WIN
    QString pixi(m_pixi + "/pixi.exe");
#else
    QString pixi(m_pixi + "/pixi");
#endif

    if (m_debug) {
      qDebug() << "Executing (package)" << pixi
               << realArgs.join(QStringLiteral(" ")) << "<" << scriptStdin;
      qDebug() << "Working directory is" << m_packageDir;
    }
    m_process->start(pixi, realArgs);

  } else {
    // --- Script file mode ---
    realArgs.prepend(m_scriptFilePath);

    // Check if the user installed the default pixi manifest
    QString pluginDir =
      QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    bool defaultManifest = hasDefaultPixiManifest(pluginDir);

    if (defaultManifest && !m_pixi.isEmpty()) {
      // Prepend "python" for .py scripts so pixi knows the interpreter
      if (m_scriptFilePath.contains(".py"))
        realArgs.prepend("python");

      realArgs.prepend("--as-is");

      // Check if the script directory (or its parent) has a .pixi directory
      QString scriptDirPath(QFileInfo(m_scriptFilePath).absolutePath());
      bool hasPixiDir = QDir(scriptDirPath + "/.pixi").exists() ||
                        QDir(scriptDirPath + "/../.pixi").exists();

      // Use the default manifest if the script doesn't have its own .pixi
      // directory and isn't in the user plugin directory (i.e., we bundled it)
      if (!pluginDir.isEmpty() && !hasPixiDir &&
          !m_scriptFilePath.startsWith(pluginDir)) {
#ifndef NDEBUG
        qDebug() << "Using manifest in" << pluginDir;
#endif
        realArgs.prepend(pluginDir);
        realArgs.prepend("--manifest-path");
      } else if (hasPixiDir || m_scriptFilePath.startsWith(pluginDir)) {
        m_process->setWorkingDirectory(scriptDirPath);
      } else {
        if (m_debug) {
          qDebug() << "No valid pixi manifest configuration found for"
                   << m_scriptFilePath;
        }
        return;
      }

      realArgs.prepend("run");

#ifdef Q_OS_WIN
      QString pixi(m_pixi + "/pixi.exe");
#else
      QString pixi(m_pixi + "/pixi");
#endif

      if (m_debug) {
        qDebug() << "Executing" << pixi << realArgs.join(QStringLiteral(" "))
                 << "<" << scriptStdin;
        qDebug() << "Working directory is" << m_process->workingDirectory();
      }
      m_process->start(pixi, realArgs);
    } else {
      // Plain python
      if (m_debug) {
        qDebug() << "Executing" << m_pythonInterpreter
                 << realArgs.join(QStringLiteral(" ")) << "<" << scriptStdin;
      }
      m_process->start(m_pythonInterpreter, realArgs);
    }
  } // end script-file mode

  // Write scriptStdin to the process's stdin
  if (!scriptStdin.isNull()) {
    if (!m_process->waitForStarted(5000)) {
      m_errors << tr("Error running script '%1 %2': Timed out waiting for "
                     "start (%3).")
                    .arg(m_process->program(),
                         realArgs.join(QStringLiteral(" ")),
                         processErrorString(*m_process));
      return;
    }

    qint64 len = m_process->write(scriptStdin);
    if (len != static_cast<qint64>(scriptStdin.size())) {
      m_errors << tr("Error running script '%1 %2': failed to write to stdin "
                     "(len=%3, wrote %4 bytes, QProcess error: %5).")
                    .arg(m_process->program())
                    .arg(realArgs.join(QStringLiteral(" ")))
                    .arg(scriptStdin.size())
                    .arg(len)
                    .arg(processErrorString(*m_process));
      return;
    }
    m_process->closeWriteChannel();
  }

  // let the script run
  connect(m_process, SIGNAL(finished(int, QProcess::ExitStatus)), this,
          SLOT(processFinished(int, QProcess::ExitStatus)));
}

void PythonScript::processFinished(int, QProcess::ExitStatus)
{
  emit finished();
}

void PythonScript::asyncTerminate()
{
  if (m_process != nullptr) {
    disconnect(m_process, nullptr, nullptr, nullptr);
    m_process->kill();
    m_process->deleteLater();
    m_process = nullptr;
  }
}

QByteArray PythonScript::asyncWriteAndResponse(QByteArray input)
{
  if (m_process == nullptr)
    return QByteArray();

  m_process->write(input);
  QByteArray buffer;
  if (m_process->waitForReadyRead()) {
    while (m_process->canReadLine())
      buffer += m_process->readLine();
  }
  return buffer;
}

QByteArray PythonScript::asyncResponse()
{
  if (m_process == nullptr || m_process->state() == QProcess::Running)
    return QByteArray();

  return m_process->readAll();
}

QString PythonScript::processErrorString(const QProcess& proc) const
{
  QString result;
  switch (proc.error()) {
    case QProcess::FailedToStart:
      result = tr("Script failed to start.");
      break;
    case QProcess::Crashed:
      result = tr("Script crashed.");
      break;
    case QProcess::Timedout:
      result = tr("Script timed out.");
      break;
    case QProcess::ReadError:
      result = tr("Read error.");
      break;
    case QProcess::WriteError:
      result = tr("Write error.");
      break;
    default:
    case QProcess::UnknownError:
      result = tr("Unknown error.");
      break;
  }
  return result;
}

} // namespace Avogadro::QtGui
