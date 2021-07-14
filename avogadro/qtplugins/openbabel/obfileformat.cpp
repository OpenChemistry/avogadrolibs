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

#include <nlohmann/json.hpp>

#include <QtCore/QCoreApplication>
#include <QtCore/QFileInfo>
#include <QtCore/QTimer>

using json = nlohmann::json;

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

  bool waitForOutput(QByteArray& output, int msTimeout = 120000)
  {
    if (!wait(msTimeout))
      return false;

    // success!
    output = m_output;
    return true;
  }

public slots:
  void responseReceived(const QByteArray& output)
  {
    m_finished = true;
    m_output = output;
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

  OBProcess* m_process;
  bool m_finished;
  QByteArray m_output;
};

OBFileFormat::OBFileFormat(const std::string& name_,
                           const std::string& identifier_,
                           const std::string& description_,
                           const std::string& specificationUrl_,
                           const std::vector<std::string> fileExtensions_,
                           const std::vector<std::string> mimeTypes_,
                           bool fileOnly_)
  : Io::FileFormat(), m_description(description_),
    m_fileExtensions(fileExtensions_), m_mimeTypes(mimeTypes_),
    m_identifier(identifier_), m_name(name_),
    m_specificationUrl(specificationUrl_), m_fileOnly(fileOnly_)
{
}

OBFileFormat::~OBFileFormat()
{
}

bool OBFileFormat::read(std::istream& in, Core::Molecule& molecule)
{
  json opts;
  if (!options().empty())
    opts = json::parse(options(), nullptr, false);
  else
    opts = json::object();

  // Allow blocking until the read is completed.
  OBProcess proc;
  ProcessListener listener;
  QObject::connect(&proc, SIGNAL(convertFinished(QByteArray)), &listener,
                   SLOT(responseReceived(QByteArray)));

  // Just grab the first file extension from the list -- all extensions for a
  // given format map to the same parsers in OB.
  if (m_fileExtensions.empty()) {
    appendError("Internal error: No file extensions set.");
    return false;
  }

  // If we are reading a pure-2D format, generate 3D coordinates:
  QStringList options;
  QStringList formats2D;
  formats2D << "smi"
            << "smiles"
            << "can"
            << "inchi"
            << "wln";
  if (formats2D.contains(QString::fromStdString(m_fileExtensions.front())))
    options << "--gen3d";

  // Check if we have extra arguments for open babel
  json extraArgs = opts.value("arguments", json::object());
  if (extraArgs.is_array()) {
    for (const auto& arg : extraArgs) {
      if (arg.is_string())
        options << arg.get<std::string>().c_str();
    }
  }

  if (!m_fileOnly) {
    // Determine length of data
    in.seekg(0, std::ios_base::end);
    std::istream::pos_type length = in.tellg();
    in.seekg(0, std::ios_base::beg);
    in.clear();

    // Extract char data
    QByteArray input;
    input.resize(static_cast<int>(length));
    in.read(input.data(), length);
    if (in.gcount() != length) {
      appendError("Error reading stream into buffer!");
      return false;
    }

    // Perform the conversion.
    if (!proc.convert(input, QString::fromStdString(m_fileExtensions.front()),
                      "cml", options)) {
      appendError("OpenBabel conversion failed!");
      return false;
    }
  } else {
    // Can only read files. Need absolute path.
    QString filename = QString::fromStdString(fileName());
    if (!QFileInfo(filename).isAbsolute()) {
      appendError("Internal error -- filename must be absolute! " +
                  filename.toStdString());
      return false;
    }

    // Perform the conversion.
    if (!proc.convert(filename,
                      QString::fromStdString(m_fileExtensions.front()), "cml",
                      options)) {
      appendError("OpenBabel conversion failed!");
      return false;
    }
  }

  QByteArray cmlOutput;
  if (!listener.waitForOutput(cmlOutput)) {
    appendError(std::string("Conversion timed out."));
    return false;
  }

  if (cmlOutput.isEmpty()) {
    appendError(std::string("OpenBabel error: conversion failed."));
    return false;
  }

  Io::CmlFormat cmlReader;
  if (!cmlReader.readString(std::string(cmlOutput.constData()), molecule)) {
    appendError(std::string("Error while reading OpenBabel-generated CML:"));
    appendError(cmlReader.error());
    return false;
  }

  return true;
}

bool OBFileFormat::write(std::ostream& out, const Core::Molecule& molecule)
{
  json opts;
  if (!options().empty())
    opts = json::parse(options(), nullptr, false);
  else
    opts = json::object();

  // Check if we have extra arguments for open babel
  QStringList options;
  json extraArgs = opts.value("arguments", json::object());
  if (extraArgs.is_array()) {
    for (const auto& arg : extraArgs) {
      if (arg.is_string())
        options << arg.get<std::string>().c_str();
    }
  }

  // Generate CML to give to OpenBabel
  std::string cml;
  Io::CmlFormat cmlWriter;
  if (!cmlWriter.writeString(cml, molecule)) {
    appendError(std::string("Error while writing CML:"));
    appendError(cmlWriter.error());
    return false;
  }

  // Block until the OpenBabel conversion finishes:
  OBProcess proc;
  ProcessListener listener;
  QObject::connect(&proc, SIGNAL(convertFinished(QByteArray)), &listener,
                   SLOT(responseReceived(QByteArray)));

  // Just grab the first file extension from the list -- all extensions for a
  // given format map to the same parsers in OB.
  if (m_fileExtensions.empty()) {
    appendError("Internal error: No file extensions set.");
    return false;
  }
  proc.convert(QByteArray(cml.c_str()), "cml",
               QString::fromStdString(m_fileExtensions.front()), options);

  QByteArray output;
  if (!listener.waitForOutput(output)) {
    appendError(std::string("Conversion timed out."));
    return false;
  }

  if (output.isEmpty()) {
    appendError(std::string("OpenBabel error: conversion failed."));
    return false;
  }

  out.write(output.constData(), output.size());

  return true;
}

void OBFileFormat::clear()
{
  Io::FileFormat::clear();
}

Io::FileFormat* OBFileFormat::newInstance() const
{
  return new OBFileFormat(m_name, m_identifier, m_description,
                          m_specificationUrl, m_fileExtensions, m_mimeTypes,
                          m_fileOnly);
}

} // namespace QtPlugins
} // namespace Avogadro

#include "obfileformat.moc"
