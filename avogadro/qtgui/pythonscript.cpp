/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "pythonscript.h"

#include "avogadropython.h"
#include "utilities.h"

#include <QtCore/QDebug>
#include <QtCore/QFileInfo>
#include <QtCore/QLocale>
#include <QtCore/QProcess>
#include <QtCore/QSettings>

namespace Avogadro::QtGui {

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
    qWarning() << "Python interpreter" << m_pythonInterpreter
               << "does not exist trying \"python\" in your path."
               << "Please set a path to the python interpreter.";

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

  // Start script
  realArgs.prepend(m_scriptFilePath);
  if (m_debug) {
    qDebug() << "Executing" << m_pythonInterpreter
             << realArgs.join(QStringLiteral(" ")) << "<" << scriptStdin;
  }
  proc.start(m_pythonInterpreter, realArgs);

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

  if (m_debug)
    qDebug() << "Output:" << result;

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

  // Start script
  realArgs.prepend(m_scriptFilePath);
  if (m_debug) {
    qDebug() << "Executing" << m_pythonInterpreter
             << realArgs.join(QStringLiteral(" ")) << "<" << scriptStdin;
  }
  m_process->start(m_pythonInterpreter, realArgs);

  // Write scriptStdin to the process's stdin
  if (!scriptStdin.isNull()) {
    if (!m_process->waitForStarted(5000)) {
      m_errors << tr("Error running script '%1 %2': Timed out waiting for "
                     "start (%3).")
                    .arg(m_pythonInterpreter,
                         realArgs.join(QStringLiteral(" ")),
                         processErrorString(*m_process));
      return;
    }

    qint64 len = m_process->write(scriptStdin);
    if (len != static_cast<qint64>(scriptStdin.size())) {
      m_errors << tr("Error running script '%1 %2': failed to write to stdin "
                     "(len=%3, wrote %4 bytes, QProcess error: %5).")
                    .arg(m_pythonInterpreter)
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
  if (m_process == nullptr) {
    return QByteArray(); // wait
  }

  m_process->write(input);
  QByteArray buffer;

  bool ready = m_process->waitForReadyRead();
  if (ready) {
    while (m_process->canReadLine()) {
      buffer += m_process->readLine();
    }
  }

  return buffer;
}

QByteArray PythonScript::asyncResponse()
{
  if (m_process == nullptr || m_process->state() == QProcess::Running) {
    return QByteArray(); // wait
  }

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
