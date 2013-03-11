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

#include "obfileformat.h"

#include "obprocess.h"

#include <avogadro/io/cmlformat.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QFileInfo>
#include <QtCore/QTimer>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The ProcessListener class allows synchronous use of OBProcess.
 */
class OBFileFormat::ProcessListener : public QObject
{
  Q_OBJECT
public:
  ProcessListener() : QObject(), m_finished(false) {}

  bool waitForOutput(QByteArray &output, int msTimeout = 120000)
  {
    if (!wait(msTimeout))
      return false;

    // success!
    output = m_output;
    return true;
  }

  bool waitForOutput(bool &output, int msTimeout = 120000)
  {
    if (!wait(msTimeout))
      return false;

    // success!
    output = m_success;
    return true;
  }

public slots:
  void responseReceived(const QByteArray &output)
  {
    m_finished = true;
    m_output = output;
  }

  void responseReceived(bool output)
  {
    m_finished = true;
    m_success = output;
  }

private:
  bool wait(int msTimeout)
  {
    QTimer timer;
    timer.start(msTimeout);

    while (timer.isActive() && !m_finished)
      qApp->processEvents(QEventLoop::AllEvents, 500);

    return m_finished;
  }

  OBProcess *m_process;
  bool m_finished;
  QByteArray m_output;
  bool m_success;
};

OBFileFormat::OBFileFormat(const std::string &name_,
                           const std::string &identifier_,
                           const std::string &description_,
                           const std::string &specificationUrl_,
                           const std::vector<std::string> fileExtensions_,
                           const std::vector<std::string> mimeTypes_)
  : Io::FileFormat(),
    m_description(description_),
    m_fileExtensions(fileExtensions_),
    m_mimeTypes(mimeTypes_),
    m_identifier(identifier_),
    m_name(name_),
    m_specificationUrl(specificationUrl_)
{
}

OBFileFormat::~OBFileFormat()
{
}

bool OBFileFormat::read(std::istream &in, Core::Molecule &molecule)
{
  Q_UNUSED(in);

  OBProcess proc;

  QFileInfo info(QString::fromStdString(fileName()));
  if (!info.exists()) {
    appendError(std::string("File does not exist: ") + fileName());
    return false;
  }

  if (!info.isReadable()) {
    appendError(std::string("File is not readable: ") + fileName());
    return false;
  }

  // Block until the read is completed.
  ProcessListener listener;
  QObject::connect(&proc, SIGNAL(readFileFinished(QByteArray)),
                   &listener, SLOT(responseReceived(QByteArray)));

  proc.readFile(info.absoluteFilePath(), "cml");

  QByteArray cmlOutput;
  if (!listener.waitForOutput(cmlOutput)) {
    appendError(std::string("Timeout while reading file: ") + fileName());
    return false;
  }

  if (cmlOutput.isEmpty()) {
    appendError(std::string("OpenBabel error while reading file: ")
                + fileName());
    return false;
  }

  Io::CmlFormat cmlReader;
  if (!cmlReader.readString(std::string(cmlOutput.constData()), molecule)) {
    appendError(std::string("Error while reading openbabel-generated CML:"));
    appendError(cmlReader.error());
    return false;
  }

  return true;
}

bool OBFileFormat::write(std::ostream &out, const Core::Molecule &molecule)
{
  Q_UNUSED(out);

  std::string cml;
  Io::CmlFormat cmlWriter;
  if (!cmlWriter.writeString(cml, molecule)) {
    appendError(std::string("Error while writing CML:"));
    appendError(cmlWriter.error());
    return false;
  }

  // Block until the write is completed.
  OBProcess proc;
  ProcessListener listener;
  QObject::connect(&proc, SIGNAL(writeFileFinished(bool)),
                   &listener, SLOT(responseReceived(bool)));

  proc.writeFile(QString::fromStdString(fileName()),
                 QByteArray(cml.c_str()), "cml");

  bool success;
  if (!listener.waitForOutput(success)) {
    appendError(std::string("Timeout while writing file: ") + fileName());
    return false;
  }

  if (!success) {
    appendError(std::string("OpenBabel error while writing file: ")
                + fileName());
    return false;
  }

  return true;
}

void OBFileFormat::clear()
{
  Io::FileFormat::clear();
}

Io::FileFormat *OBFileFormat::newInstance()
{
  return new OBFileFormat(m_name, m_identifier, m_description,
                          m_specificationUrl, m_fileExtensions, m_mimeTypes);
}

} // namespace QtPlugins
} // namespace Avogadro

#include "obfileformat.moc"
