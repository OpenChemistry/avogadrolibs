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

#include "pythonscript.h"

#include "avogadropython.h"

#include <QtCore/QDebug>
#include <QtCore/QLocale>
#include <QtCore/QProcess>
#include <QtCore/QSettings>

namespace Avogadro {
namespace QtGui {

PythonScript::PythonScript(const QString& scriptFilePath_, QObject* parent_)
  : QObject(parent_)
  , m_debug(!qgetenv("AVO_PYTHON_SCRIPT_DEBUG").isEmpty())
  , m_scriptFilePath(scriptFilePath_)
{
  setDefaultPythonInterpretor();
}

PythonScript::PythonScript(QObject* parent_)
  : QObject(parent_)
  , m_debug(!qgetenv("AVO_PYTHON_SCRIPT_DEBUG").isEmpty())
{
  setDefaultPythonInterpretor();
}

PythonScript::~PythonScript() {}

void PythonScript::setScriptFilePath(const QString& scriptFile)
{
  m_scriptFilePath = scriptFile;
}

void PythonScript::setDefaultPythonInterpretor()
{
  m_pythonInterpreter = qgetenv("AVO_PYTHON_INTERPRETER");
  if (m_pythonInterpreter.isEmpty()) {
    m_pythonInterpreter =
      QSettings().value(QStringLiteral("interpreters/python")).toString();
  }
  if (m_pythonInterpreter.isEmpty())
    m_pythonInterpreter = pythonInterpreterPath;
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
  realArgs.append(QLocale::system().name());

  // Start script
  realArgs.prepend(m_scriptFilePath);
  if (m_debug) {
    qDebug() << "Executing" << m_pythonInterpreter
             << realArgs.join(QStringLiteral(" ")) << "<" << scriptStdin;
  }
  proc.start(m_pythonInterpreter, realArgs);

  // Write scriptStdin to the process's stdin
  if (!scriptStdin.isNull()) {
    if (!proc.waitForStarted(5000)) {
      m_errors << tr("Error running script '%1 %2': Timed out waiting for "
                     "start (%3).")
                    .arg(m_pythonInterpreter,
                         realArgs.join(QStringLiteral(" ")),
                         processErrorString(proc));
      return QByteArray();
    }

    qint64 len = proc.write(scriptStdin);
    if (len != static_cast<qint64>(scriptStdin.size())) {
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

  if (!proc.waitForFinished(5000)) {
    m_errors << tr("Error running script '%1 %2': Timed out waiting for "
                   "finish (%3).")
                  .arg(m_pythonInterpreter, realArgs.join(QStringLiteral(" ")),
                       processErrorString(proc));
    return QByteArray();
  }

  if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0) {
    m_errors << tr("Error running script '%1 %2': Abnormal exit status %3 "
                   "(%4: %5)\n\nOutput:\n%6")
                  .arg(m_pythonInterpreter)
                  .arg(realArgs.join(QStringLiteral(" ")))
                  .arg(proc.exitCode())
                  .arg(processErrorString(proc))
                  .arg(proc.errorString())
                  .arg(QString(proc.readAll()));
    return QByteArray();
  }

  QByteArray result(proc.readAll());

  if (m_debug)
    qDebug() << "Output:" << result;

  return result;
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

} // namespace QtGui
} // namespace Avogadro
