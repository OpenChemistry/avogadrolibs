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
#include <QtCore/QJsonDocument>
#include <QtCore/QLocale>
#include <QtCore/QProcess>
#include <QtCore/QProcessEnvironment>
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
  m_packageDir.clear();
  m_packageCommand.clear();
  m_packageIdentifier.clear();
  m_packageDisplayName.clear();
}

void PythonScript::setPackageInfo(const QString& packageDir,
                                  const QString& command,
                                  const QString& identifier,
                                  const QString& displayName)
{
  m_packageDir = packageDir;
  m_packageCommand = command;
  m_packageIdentifier = identifier;
  m_packageDisplayName = displayName;
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

QString PythonScript::resolveCommand(QStringList& realArgs, QProcess& proc)
{
#ifdef Q_OS_WIN
  QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
  environment.insert(QStringLiteral("PYTHONUTF8"), QStringLiteral("1"));
  proc.setProcessEnvironment(environment);
#endif

  // --- Package mode: pixi run <command> <identifier> [args] ---
  if (m_packageMode) {
    if (m_pixi.isEmpty()) {
      m_errors << tr("Package mode requires pixi but it was not found.");
      return QString();
    }

    realArgs.prepend(m_packageIdentifier);
    realArgs.prepend(m_packageCommand);
    realArgs.prepend("--as-is");
    realArgs.prepend("run");

    proc.setWorkingDirectory(m_packageDir);

#ifdef Q_OS_WIN
    return m_pixi + "/pixi.exe";
#else
    return m_pixi + "/pixi";
#endif
  }

  // --- Script file mode ---
  realArgs.prepend(m_scriptFilePath);

  // Check if the user installed the default pixi manifest
  QString pluginDir =
    QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
  bool defaultManifest = hasDefaultPixiManifest(pluginDir);

  if (!defaultManifest || m_pixi.isEmpty()) {
    // Plain python — no pixi available
    return m_pythonInterpreter;
  }

  // Prepend "python" for .py scripts so pixi knows the interpreter
  if (m_scriptFilePath.endsWith(".py"))
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
    return QString();
  }

  realArgs.prepend("run");

#ifdef Q_OS_WIN
  return m_pixi + "/pixi.exe";
#else
  return m_pixi + "/pixi";
#endif
}

QByteArray PythonScript::execute(const QStringList& args,
                                 const QByteArray& scriptStdin)
{
  clearErrors();
  QProcess proc;
  proc.setProcessChannelMode(QProcess::SeparateChannels);

  QStringList realArgs(args);
  if (m_debug)
    realArgs.prepend(QStringLiteral("--debug"));
  realArgs.append("--lang");
  realArgs.append(QLocale().name());

  QString program = resolveCommand(realArgs, proc);
  if (program.isEmpty())
    return QByteArray();

  if (m_debug) {
    qDebug() << "Executing" << program << realArgs.join(QStringLiteral(" "))
             << "<" << scriptStdin;
    if (!proc.workingDirectory().isEmpty())
      qDebug() << "Working directory is" << proc.workingDirectory();
  }
  proc.start(program, realArgs);

  // Write scriptStdin to the process's stdin
  if (!scriptStdin.isNull()) {
    if (!proc.waitForStarted(10000)) {
      m_errors << tr("Error running script '%1 %2': Timed out waiting for "
                     "start (%3).")
                    .arg(program, realArgs.join(QStringLiteral(" ")),
                         processErrorString(proc));
      return QByteArray();
    }

    qint64 len = proc.write(scriptStdin);
    if (len != static_cast<qint64>(scriptStdin.size()) && m_debug) {
      m_errors << tr("Error running script '%1 %2': failed to write to stdin "
                     "(len=%3, wrote %4 bytes, QProcess error: %5).")
                    .arg(program)
                    .arg(realArgs.join(QStringLiteral(" ")))
                    .arg(scriptStdin.size())
                    .arg(len)
                    .arg(processErrorString(proc));
      return QByteArray();
    }
    proc.closeWriteChannel();
  }

  if (!proc.waitForFinished(10000)) {
    if (m_debug)
      m_errors << tr("Error running script '%1 %2': Timed out waiting for "
                     "finish (%3).")
                    .arg(program, realArgs.join(QStringLiteral(" ")),
                         processErrorString(proc));
    proc.kill();
    return QByteArray();
  }

  if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0) {
    if (m_debug)
      m_errors << tr("Error running script '%1 %2': Abnormal exit status %3 "
                     "(%4: %5)\n\nOutput:\n%6")
                    .arg(program)
                    .arg(realArgs.join(QStringLiteral(" ")))
                    .arg(proc.exitCode())
                    .arg(processErrorString(proc))
                    .arg(proc.errorString())
                    .arg(QString(proc.readAllStandardOutput()) +
                         QString(proc.readAllStandardError()));
    else
      m_errors << tr("Warning '%1'").arg(proc.errorString());
    return QByteArray();
  }

  QByteArray result(proc.readAllStandardOutput());
  QByteArray stderrOutput(proc.readAllStandardError());

  if (m_debug) {
    if (!stderrOutput.isEmpty())
      qDebug() << "Script stderr:" << stderrOutput;

    qDebug() << "Output:" << result;
    qDebug() << " Errors: " << m_errors;
  }

  return result;
}

bool PythonScript::asyncExecute(const QStringList& args,
                                const QByteArray& scriptStdin,
                                bool mergedChannels, bool closeWriteChannel)
{
  clearErrors();
  if (m_process != nullptr) {
    m_process->terminate();
    // Sever every connection, not just finished(): the abandoned process is
    // still alive until deleteLater() runs, and its signals would otherwise
    // arrive while m_process already points at the replacement.
    disconnect(m_process, nullptr, this, nullptr);
    m_process->deleteLater();
  }
  m_process = new QProcess(parent());

  if (mergedChannels)
    m_process->setProcessChannelMode(QProcess::MergedChannels);

  m_stdoutBuffer.clear();
  m_stderrBuffer.clear();
  m_lineBuffer.clear();
  if (m_scanProgress) {
    // Drain both channels as they arrive so progress envelopes can be acted on
    // while the script is still running.
    connect(m_process, &QProcess::readyReadStandardOutput, this,
            &PythonScript::readAsyncStandardOutput);
    connect(m_process, &QProcess::readyReadStandardError, this,
            &PythonScript::readAsyncStandardError);
  }

  QStringList realArgs(args);
  if (m_debug)
    realArgs.prepend(QStringLiteral("--debug"));
  realArgs.append("--lang");
  realArgs.append(QLocale().name());

  QString program = resolveCommand(realArgs, *m_process);
  if (program.isEmpty()) {
    // resolveCommand() failed to work out how to launch the script. It may
    // have recorded why in m_errors, but nothing downstream drains that list
    // when no process is ever started, so report it here.
    m_errors << tr("Error running script '%1': could not resolve a command to "
                   "run it (no python interpreter or pixi environment).")
                  .arg(realArgs.join(QStringLiteral(" ")));
    qWarning() << "PythonScript::asyncExecute failed:" << m_errors.join("\n");
    return false;
  }

  if (m_debug) {
    qDebug() << "Executing" << program << realArgs.join(QStringLiteral(" "))
             << "<" << scriptStdin;
    if (!m_process->workingDirectory().isEmpty())
      qDebug() << "Working directory is" << m_process->workingDirectory();
  }
  m_process->start(program, realArgs);

  // Write scriptStdin to the process's stdin
  if (!scriptStdin.isNull()) {
    if (!m_process->waitForStarted(5000)) {
      m_errors << tr("Error running script '%1 %2': Timed out waiting for "
                     "start (%3).")
                    .arg(program, realArgs.join(QStringLiteral(" ")),
                         processErrorString(*m_process));
      qWarning() << "PythonScript::asyncExecute failed:" << m_errors.join("\n");
      return false;
    }

    qint64 len = m_process->write(scriptStdin);
    if (len != static_cast<qint64>(scriptStdin.size())) {
      m_errors << tr("Error running script '%1 %2': failed to write to stdin "
                     "(len=%3, wrote %4 bytes, QProcess error: %5).")
                    .arg(program)
                    .arg(realArgs.join(QStringLiteral(" ")))
                    .arg(scriptStdin.size())
                    .arg(len)
                    .arg(processErrorString(*m_process));
      qWarning() << "PythonScript::asyncExecute failed:" << m_errors.join("\n");
      return false;
    }
    if (closeWriteChannel)
      m_process->closeWriteChannel();
  }

  // let the script run
  connect(m_process, SIGNAL(finished(int, QProcess::ExitStatus)), this,
          SLOT(processFinished(int, QProcess::ExitStatus)));
  return true;
}

void PythonScript::processFinished(int, QProcess::ExitStatus)
{
  if (m_scanProgress && m_process != nullptr) {
    // readyRead() may not have fired for the last chunk, and a script's final
    // line is not guaranteed to end with a newline.
    readAsyncStandardError();
    readAsyncStandardOutput();
    if (!m_lineBuffer.isEmpty()) {
      QJsonObject payload;
      if (parseProgressEnvelope(m_lineBuffer, payload))
        emit asyncProgress(payload);
      else
        m_stdoutBuffer += m_lineBuffer;
      m_lineBuffer.clear();
    }

    if (m_debug && !m_stderrBuffer.isEmpty())
      qDebug() << "Script standard error:" << m_stderrBuffer;
  }

  emit finished();
}

bool PythonScript::parseProgressEnvelope(const QByteArray& line,
                                         QJsonObject& payload)
{
  // Reject cheaply first: the result blob may be large and pretty-printed, and
  // running the JSON parser over every one of its lines is wasted work.
  const QByteArray trimmed = line.trimmed();
  if (!trimmed.startsWith('{') || !trimmed.contains("\"avogadro\""))
    return false;

  QJsonParseError error;
  const QJsonDocument doc = QJsonDocument::fromJson(trimmed, &error);
  if (error.error != QJsonParseError::NoError || !doc.isObject())
    return false;

  // Require exactly one member, named "avogadro". A result object that merely
  // happens to carry an "avogadro" key alongside others is not an envelope.
  const QJsonObject object = doc.object();
  if (object.size() != 1)
    return false;

  // The member must be an object. A scalar or null payload would otherwise
  // yield an empty payload from toObject() and silently swallow the line.
  const QJsonValue value = object.value(QStringLiteral("avogadro"));
  if (!value.isObject())
    return false;

  payload = value.toObject();
  return true;
}

void PythonScript::filterProgressLines(QByteArray& buffer, QByteArray& output,
                                       QList<QJsonObject>& payloads)
{
  qsizetype start = 0;
  qsizetype newline = buffer.indexOf('\n');
  QJsonObject payload;
  while (newline >= 0) {
    if (parseProgressEnvelope(buffer.mid(start, newline - start), payload))
      payloads.append(payload);
    else // keep the line verbatim, newline included
      output += buffer.mid(start, newline - start + 1);
    start = newline + 1;
    newline = buffer.indexOf('\n', start);
  }
  buffer.remove(0, start);
}

void PythonScript::readAsyncStandardOutput()
{
  if (m_process == nullptr)
    return;

  m_lineBuffer += m_process->readAllStandardOutput();
  QList<QJsonObject> payloads;
  filterProgressLines(m_lineBuffer, m_stdoutBuffer, payloads);
  for (const QJsonObject& payload : payloads)
    emit asyncProgress(payload);
}

void PythonScript::readAsyncStandardError()
{
  if (m_process == nullptr)
    return;

  m_stderrBuffer += m_process->readAllStandardError();
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

QByteArray PythonScript::asyncWriteAndResponseRaw(const QByteArray& input,
                                                  int timeoutMs)
{
  if (m_process == nullptr) {
    return QByteArray(); // wait
  }

  if (!input.isEmpty()) {
    const qint64 len = m_process->write(input);
    if (len != static_cast<qint64>(input.size())) {
      m_errors << tr("Error writing raw request to script stdin (len=%1, wrote "
                     "%2 bytes, QProcess error: %3).")
                    .arg(input.size())
                    .arg(len)
                    .arg(processErrorString(*m_process));
      return QByteArray();
    }
  }

  QByteArray buffer;
  if (!m_process->waitForReadyRead(timeoutMs)) {
    return buffer;
  }

  buffer += m_process->readAll();
  // Keep draining while data arrives immediately (no artificial delay).
  while (m_process->waitForReadyRead(0)) {
    buffer += m_process->readAll();
  }
  return buffer;
}

QByteArray PythonScript::asyncResponse()
{
  if (m_scanProgress) {
    // Standard output was drained as it arrived, so the buffer is complete
    // (and outlives the process) once the script has finished.
    if (m_process != nullptr && m_process->state() == QProcess::Running)
      return QByteArray();

    return m_stdoutBuffer;
  }

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
