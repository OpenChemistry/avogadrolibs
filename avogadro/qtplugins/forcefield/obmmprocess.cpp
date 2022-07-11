/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2019 Geoffrey R. Hutchison

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "OBMMProcess.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QProcess>
#include <QtCore/QRegExp>

namespace Avogadro {
namespace QtPlugins {

OBMMProcess::OBMMProcess(QObject* parent_)
  : QObject(parent_), m_processLocked(false), m_aborted(false),
    m_process(new QProcess(this)),
#if defined(_WIN32)
    m_obmmExecutable("obmm.exe")
#else
    m_obmmExecutable("obmm")
#endif
{
  // Read the AVO_OBABEL_EXECUTABLE env var to optionally override the
  // executable used.
  QByteArray obmmExec = qgetenv("AVO_OBMM_EXECUTABLE");
  if (!obabelExec.isEmpty()) {
    m_obmmExecutable = obmmExec;
  } else {
    // If not overridden, look for an obabel next to the executable.
    QDir baseDir(QCoreApplication::applicationDirPath());
    if (!baseDir.absolutePath().startsWith("/usr/") &&
        QFileInfo(baseDir.absolutePath() + '/' + m_obabelExecutable).exists()) {
      m_obabelExecutable = baseDir.absolutePath() + '/' + m_obmmExecutable;
      QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
#if defined(_WIN32)
      env.insert("BABEL_DATADIR",
                 QCoreApplication::applicationDirPath() + "/data");
#else
      QDir dir(QCoreApplication::applicationDirPath() + "/../share/openbabel");
      QStringList filters;
      filters << "2.*";
      QStringList dirs = dir.entryList(filters);
      if (dirs.size() == 1) {
        env.insert("BABEL_DATADIR", QCoreApplication::applicationDirPath() +
                                      "/../share/openbabel/" + dirs[0]);
      } else {
        qDebug() << "Error, Open Babel data directory not found.";
      }
      dir.setPath(QCoreApplication::applicationDirPath() + "/../lib/openbabel");
      dirs = dir.entryList(filters);
      if (dirs.size() == 1) {
        env.insert("BABEL_LIBDIR", QCoreApplication::applicationDirPath() +
                                     "/../lib/openbabel/" + dirs[0]);
      } else {
        qDebug() << "Error, Open Babel plugins directory not found.";
      }
#endif
      m_process->setProcessEnvironment(env);
    }
  }
}

void OBMMProcess::abort()
{
  m_aborted = true;
  emit aborted();
}

void OBMMProcess::obError()
{
  qDebug() << "Process encountered an error, and did not execute correctly.";
  if (m_process) {
    qDebug() << "\tExit code:" << m_process->exitCode();
    qDebug() << "\tExit status:" << m_process->exitStatus();
    qDebug() << "\tExit output:" << m_process->readAll();
  }
}

bool OBMMProcess::queryForceFields()
{
  if (!tryLockProcess()) {
    qWarning() << "OBMMProcess::queryForceFields(): process already in use.";
    return false;
  }

  QStringList options;
  options << "-L"
          << "forcefields";

  executeObabel(options, this, SLOT(queryForceFieldsPrepare()));
  return true;
}

void OBMMProcess::queryForceFieldsPrepare()
{
  if (m_aborted) {
    releaseProcess();
    return;
  }

  QMap<QString, QString> result;

  QString output = QString::fromLatin1(m_process->readAllStandardOutput());

  QRegExp parser("([^\\s]+)\\s+(\\S[^\\n]*[^\\n\\.]+)\\.?\\n");
  int pos = 0;
  while ((pos = parser.indexIn(output, pos)) != -1) {
    QString key = parser.cap(1);
    QString desc = parser.cap(2);
    result.insertMulti(key, desc);
    pos += parser.matchedLength();
  }

  releaseProcess();
  emit queryForceFieldsFinished(result);
}

void OBMMProcess::executeObabel(const QStringList& options, QObject* receiver,
                              const char* slot, const QByteArray& obabelStdin)
{
  // Setup exit handler
  if (receiver) {
    connect(m_process, SIGNAL(finished(int)), receiver, slot);
    connect(m_process, SIGNAL(error(QProcess::ProcessError)), receiver, slot);
    connect(m_process, SIGNAL(error(QProcess::ProcessError)), this,
            SLOT(obError()));
  }

  // Start process
  qDebug() << "OBMMProcess::executeObabel: "
              "Running"
           << m_obabelExecutable << options.join(" ");
  m_process->start(m_obabelExecutable, options);
  if (!obabelStdin.isNull()) {
    m_process->write(obabelStdin);
    m_process->closeWriteChannel();
  }
}

void OBMMProcess::resetState()
{
  m_aborted = false;
  m_process->disconnect(this);
  disconnect(m_process);
  connect(this, SIGNAL(aborted()), m_process, SLOT(kill()));
}

} // namespace QtPlugins
} // namespace Avogadro
