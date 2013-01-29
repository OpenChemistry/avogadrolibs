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
  m_obabelExecutable("obabel")
{
  // Read the AVO_OBABEL_EXECUTABLE env var to optionally override the
  // executable used for obabel.
  QByteArray obabelExec = qgetenv("AVO_OBABEL_EXECUTABLE");
  if (!obabelExec.isEmpty())
    m_obabelExecutable = obabelExec;
}

void OBProcess::queryReadFormats()
{
  // Setup options
  QStringList options;
  options << "-L" << "formats" << "read";

  // Create process
  QProcess *proc = new QProcess(this);

  // Setup exit handler
  connect(proc, SIGNAL(finished(int)),
          SLOT(queryReadFormatsPrepare()));
  connect(proc, SIGNAL(error(QProcess::ProcessError)),
          SLOT(queryReadFormatsPrepare()));

  // Start the process
  proc->start(m_obabelExecutable, options);
  qDebug() << "Requesting read formats";
}

void OBProcess::queryReadFormatsPrepare()
{
  qDebug() << "Read formats finished!";
  QMap<QString, QString> result;

  QProcess *proc = qobject_cast<QProcess*>(sender());
  if (!proc) {
    qWarning() << "Internal error: OBProcess::queryReadFormatsPrepare(): "
                  "sender() is not a QProcess!";
    emit queryReadFormatsFinished(result);
    return;
  }

  QString output = QString::fromLatin1(proc->readAllStandardOutput());
  proc->deleteLater();

  QRegExp parser("\\s*([^\\s]+)\\s+--\\s+([^\\n]+)\\n");
  int pos = 0;
  while ((pos = parser.indexIn(output, pos)) != -1) {
    QString extension = parser.cap(1);
    QString description = parser.cap(2);
    result.insertMulti(description, extension);
    pos += parser.matchedLength();
  }
  emit queryReadFormatsFinished(result);
}

void OBProcess::readFile(const QString &filename,
                         const QString &outputFormat,
                         const QString &inputFormatOverride)
{
  QStringList options;

  // Setup input options
  options << QString("-i%1").arg(!inputFormatOverride.isEmpty()
                                 ? inputFormatOverride
                                 : QFileInfo(filename).suffix());
  options << filename;

  // Setup output options
  options << QString("-o%1").arg(outputFormat);

  // Create process
  QProcess *proc = new QProcess(this);

  // Setup exit handler
  connect(proc, SIGNAL(finished(int)),
          SLOT(readFilePrepareOutput()));
  connect(proc, SIGNAL(error(QProcess::ProcessError)),
          SLOT(readFilePrepareOutput()));

  // Start process
  proc->start(m_obabelExecutable, options);
}

void OBProcess::readFilePrepareOutput()
{
  QProcess *proc = qobject_cast<QProcess*>(sender());
  if (!proc) {
    emit readFileFinished(QByteArray());
    return;
  }

  /// @todo Error handling.
  QByteArray output = proc->readAllStandardOutput();
  proc->deleteLater();

  emit readFileFinished(output);
}

} // namespace QtPlugins
} // namespace Avogadro
