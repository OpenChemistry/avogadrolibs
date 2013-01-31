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

#include "obprocess.h"

#include <QtCore/QDebug>
#include <QtCore/QFileInfo>
#include <QtCore/QProcess>

namespace Avogadro {
namespace QtPlugins {

OBProcess::OBProcess(QObject *parent_) :
  QObject(parent_),
  m_processLocked(false),
  m_aborted(false),
  m_process(new QProcess(this)),
  m_obabelExecutable("obabel")
{
  // Read the AVO_OBABEL_EXECUTABLE env var to optionally override the
  // executable used for obabel.
  QByteArray obabelExec = qgetenv("AVO_OBABEL_EXECUTABLE");
  if (!obabelExec.isEmpty())
    m_obabelExecutable = obabelExec;
}

void OBProcess::abort()
{
  m_aborted = true;
  emit aborted();
}

bool OBProcess::queryReadFormats()
{
  if (!tryLockProcess()) {
    qWarning() << "OBProcess::queryReadFormats: process already in use.";
    return false;
  }

  // Setup options
  QStringList options;
  options << "-L" << "formats" << "read";

  executeObabel(options, this, SLOT(queryReadFormatsPrepare()));
  return true;
}

void OBProcess::queryReadFormatsPrepare()
{
  if (m_aborted) {
    releaseProcess();
    return;
  }

  QMap<QString, QString> result;

  QString output = QString::fromLatin1(m_process->readAllStandardOutput());

  QRegExp parser("\\s*([^\\s]+)\\s+--\\s+([^\\n]+)\\n");
  int pos = 0;
  while ((pos = parser.indexIn(output, pos)) != -1) {
    QString extension = parser.cap(1);
    QString description = parser.cap(2);
    result.insertMulti(description, extension);
    pos += parser.matchedLength();
  }

  releaseProcess();
  emit queryReadFormatsFinished(result);
  return;
}

bool OBProcess::readFile(const QString &filename,
                         const QString &outputFormat,
                         const QString &inputFormatOverride)
{
  if (!tryLockProcess()) {
    qWarning() << "OBProcess::readFile: process already in use.";
    return false;
  }

  // Setup input options
  QStringList options;
  options << QString("-i%1").arg(!inputFormatOverride.isEmpty()
                                 ? inputFormatOverride
                                 : QFileInfo(filename).suffix());
  options << filename;

  // Setup output options
  options << QString("-o%1").arg(outputFormat);

  executeObabel(options, this, SLOT(readFilePrepareOutput()));
  return true;
}

void OBProcess::readFilePrepareOutput()
{
  if (m_aborted) {
    releaseProcess();
    return;
  }

  // Keep this empty if an error occurs:
  QByteArray output;

  // Check for errors.
  QString errorOutput = QString::fromLatin1(m_process->readAllStandardError());
  QRegExp errorChecker("\\b0 molecules converted\\b" "|"
                       "obabel: cannot read input format!");
  if (!errorOutput.contains(errorChecker)) {
    if (m_process->exitStatus() == QProcess::NormalExit)
      output = m_process->readAllStandardOutput();
  }

  /// Print any meaningful warnings @todo This should go to a log at some point.
  if (!errorOutput.isEmpty() && errorOutput != "1 molecule converted\n")
    qDebug() << m_obabelExecutable << " stderr:\n" << errorOutput;

  emit readFileFinished(output);
  releaseProcess();
}

void OBProcess::executeObabel(const QStringList &options,
                              QObject *receiver, const char *slot)
{
  // Setup exit handler
  connect(m_process, SIGNAL(finished(int)), receiver, slot);
  connect(m_process, SIGNAL(error(QProcess::ProcessError)), receiver, slot);

  // Start process
  m_process->start(m_obabelExecutable, options);
}

void OBProcess::resetState()
{
  m_aborted = false;
  m_process->disconnect(this);
  disconnect(m_process);
  connect(this, SIGNAL(aborted()), m_process, SLOT(kill()));
}

} // namespace QtPlugins
} // namespace Avogadro
