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

#include "inputgenerator.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <qjsondocument.h>
#include <qjsonarray.h>

#include <QtCore/QDebug>
#include <QtCore/QProcess>
#include <QtCore/QScopedPointer>
#include <QtCore/QTextStream>

#include <string>

namespace Avogadro {
namespace QtPlugins {

InputGenerator::InputGenerator(const QString &scriptFilePath_)
  : m_debug(!qgetenv("AVO_QM_INPUT_DEBUG").isEmpty()),
    m_moleculeExtension("Unknown"),
    m_scriptFilePath(scriptFilePath_),
    m_displayName(),
    m_options()
{
}

InputGenerator::~InputGenerator()
{
}

QJsonObject InputGenerator::options() const
{
  m_errors.clear();
  if (m_options.isEmpty()) {
    // Retrieve/set options
    QByteArray json = execute(QStringList() << "--print-options");
    QJsonDocument doc;
    if (!parseJson(json, doc))
      return m_options;

    if (!doc.isObject()) {
      m_errors << tr("script --print-options output must be an JSON object "
                     "at top level. Received:\n%1").arg(json.constData());
      return m_options;
    }

    m_options = doc.object();

    // Check if the generator needs to read a molecule.
    m_moleculeExtension = "None";
    if (m_options.contains("inputMoleculeFormat") &&
        m_options["inputMoleculeFormat"].isString()) {
      m_moleculeExtension = m_options["inputMoleculeFormat"].toString();
    }
  }

  return m_options;
}

QString InputGenerator::displayName() const
{
  m_errors.clear();
  if (m_displayName.isEmpty()) {
    m_displayName = QString(execute(QStringList() << "--display-name"));
    m_displayName = m_displayName.trimmed();
  }

  return m_displayName;
}

bool InputGenerator::generateInput(const QJsonObject &options_,
                                   const Core::Molecule &mol)
{
  m_errors.clear();
  m_filenames.clear();
  m_files.clear();

  // Add the molecule file to the options
  QJsonObject allOptions;
  allOptions["options"] = options_;
  if (!insertMolecule(allOptions, mol))
    return false;

  QByteArray json(execute(QStringList() << "--generate-input",
                          QJsonDocument(allOptions).toJson()));

  QJsonDocument doc;
  if (!parseJson(json, doc))
    return false;

  // Update cache
  bool result = true;
  if (doc.isObject()) {
    QJsonObject obj = doc.object();
    if (obj.contains("files")) {
      if (obj["files"].isArray()) {
        foreach (const QJsonValue &file, obj["files"].toArray()) {
          if (file.isObject()) {
            QJsonObject fileObj = file.toObject();
            if (fileObj["filename"].isString() &&
                fileObj["contents"].isString()) {
              QString contents = fileObj["contents"].toString();
              replaceKeywords(contents, mol);
              m_filenames << fileObj["filename"].toString();
              m_files.insert(fileObj["filename"].toString(), contents);
            }
            else {
              result = false;
              m_errors << tr("Malformed file entry: filename/contents missing"
                             " or not strings:\n%1")
                          .arg(QString(QJsonDocument(fileObj).toJson()));
            }
          }
          else {
            result = false;
            m_errors << tr("Malformed file entry at index %1: Not an object.")
                        .arg(m_filenames.size());
          }
        } // End foreach
      }
      else {
        result = false;
        m_errors << tr("'files' member not an array.");
      }
    }
    else {
      result = false;
      m_errors << tr("'files' member missing.");
    }
  }
  else {
    result = false;
    m_errors << tr("Response must be a JSON object at top-level.");
  }

  if (result == false)
    m_errors << tr("Script output:\n%1").arg(QString(json));

  return result;
}

int InputGenerator::numberOfInputFiles() const
{
  return m_filenames.size();
}

QStringList InputGenerator::fileNames() const
{
  return m_filenames;
}

QString InputGenerator::fileContents(const QString &fileName) const
{
  return m_files.value(fileName, QString());
}

QByteArray InputGenerator::execute(const QStringList &args,
                                   const QByteArray &scriptStdin) const
{
  QProcess proc;

  // Merge stdout and stderr
  proc.setProcessChannelMode(QProcess::MergedChannels);

  // Add debugging flag if needed.
  QStringList realArgs(args);
  if (m_debug) {
    realArgs.prepend("--debug");
    qDebug() << "Executing" << m_scriptFilePath << realArgs.join(" ")
             << "<" << scriptStdin;
  }

  // Start script
  proc.start(m_scriptFilePath, realArgs);

  // Write scriptStdin to the process's stdin
  if (!scriptStdin.isNull()) {
    if (!proc.waitForStarted(5000)) {
      m_errors << tr("Error running script '%1 %2': Timed out waiting for "
                     "start (%3).")
                  .arg(m_scriptFilePath, realArgs.join(" "),
                       processErrorString(proc));
      return QByteArray();
    }

    int len = proc.write(scriptStdin);
    if (len != scriptStdin.size()) {
      m_errors << tr("Error running script '%1 %2': failed to write to stdin "
                     "(len=%3, wrote %4 bytes, QProcess error: %5).")
                  .arg(m_scriptFilePath).arg(realArgs.join(" "))
                  .arg(scriptStdin.size()).arg(len)
                  .arg(processErrorString(proc));
      return QByteArray();
    }
    proc.closeWriteChannel();
  }

  if (!proc.waitForFinished(5000)) {
    m_errors << tr("Error running script '%1 %2': Timed out waiting for "
                   "finish (%3).")
                .arg(m_scriptFilePath, realArgs.join(" "),
                     processErrorString(proc));
    return QByteArray();
  }

  QByteArray result(proc.readAll());

  if (m_debug)
    qDebug() << "Output:" << result;

  return result;
}

bool InputGenerator::parseJson(const QByteArray &json, QJsonDocument &doc) const
{
  QJsonParseError error;
  doc = QJsonDocument::fromJson(json, &error);

  if (error.error != QJsonParseError::NoError) {
    m_errors << tr("Parse error at offset %L1: '%2'\nRaw JSON:\n\n%3")
                .arg(error.offset).arg(error.errorString()).arg(QString(json));
    return false;
  }
  return true;
}

QString InputGenerator::processErrorString(const QProcess &proc) const
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

bool InputGenerator::insertMolecule(QJsonObject &json,
                                    const Core::Molecule &mol) const
{
  // Update the cached options if the format is not set
  if (m_moleculeExtension == "Unknown")
    options();

  if (m_moleculeExtension == "None")
    return true;

  Io::FileFormatManager &formats = Io::FileFormatManager::instance();
  QScopedPointer<Io::FileFormat> format(formats.newFormatFromFileExtension(
                                          m_moleculeExtension.toStdString()));

  if (format.isNull()) {
    m_errors << tr("Error writing molecule representation to string: "
                   "Unrecognized file format: %1").arg(m_moleculeExtension);
    return false;
  }

  std::string str;
  if (format->writeString(str, mol)) {
    m_errors << tr("Error writing molecule representation to string: %1")
                   .arg(QString::fromStdString(format->error()));
    return false;
  }

  json.insert(m_moleculeExtension, QJsonValue(QString::fromStdString(str)));

  return true;
}

QString InputGenerator::generateCoordinateBlock(const QString &spec,
                                                const Core::Molecule &mol) const
{
  // Coordinate blocks:
  // $$coords:<spec>$$ where <spec> is a character string indicating the
  // atom attributes to print:
  // - 'Z': Atomic number
  // - 'S': Element symbol
  // - 'N': Element name
  // - 'x': x coordinate
  // - 'y': y coordinate
  // - 'z': z coordinate
  bool needElementSymbol = spec.contains('S');
  bool needElementName = spec.contains('N');
  bool needPosition =
      spec.contains('x') || spec.contains('y') || spec.contains('z');

  // Loop variables
  size_t numAtoms = mol.atomCount();
  Core::Atom atom;
  unsigned char atomicNumber;
  const char *symbol;
  const char *name;
  Vector3 pos3d;
  QString::const_iterator it;
  QString::const_iterator begin = spec.constBegin();
  QString::const_iterator end = spec.constEnd();

  // The replacement string and text stream
  QString replacement;
  QTextStream stream(&replacement);
  stream.setRealNumberNotation(QTextStream::FixedNotation);
  stream.setRealNumberPrecision(6);
  // Field width for real numbers:
  const int realWidth = 11;

  // Generate the replacement block
  for (size_t atom_i = 0; atom_i < numAtoms; ++atom_i) {
    atom = mol.atom(atom_i);
    atomicNumber = atom.atomicNumber();
    if (needElementSymbol)
      symbol = Core::Elements::symbol(atomicNumber);
    if (needElementName)
      name = Core::Elements::name(atomicNumber);
    if (needPosition)
      pos3d = atom.position3d();

    it = begin;
    while (it != end) {
      switch (it->toLatin1()) {
      case 'Z':
        stream.setFieldAlignment(QTextStream::AlignLeft);
        stream.setFieldWidth(3);
        stream << static_cast<int>(atomicNumber);
        break;
      case 'S':
        stream.setFieldAlignment(QTextStream::AlignLeft);
        stream.setFieldWidth(3);
        stream << symbol;
        break;
      case 'N':
        stream.setFieldAlignment(QTextStream::AlignLeft);
        stream.setFieldWidth(13); // longest name is currently 13 char
        stream << name;
        break;
      case 'x':
        stream.setFieldAlignment(QTextStream::AlignRight);
        stream.setFieldWidth(realWidth);
        stream << pos3d.x();
        break;
      case 'y':
        stream.setFieldAlignment(QTextStream::AlignRight);
        stream.setFieldWidth(realWidth);
        stream << pos3d.y();
        break;
      case 'z':
        stream.setFieldAlignment(QTextStream::AlignRight);
        stream.setFieldWidth(realWidth);
        stream << pos3d.z();
        break;
      } // end switch

      stream.setFieldWidth(1);
      stream << (++it != end ? " " : "\n");
    } // end while
  } // end for atom

  // Remove the final newline
  replacement.chop(1);
  return replacement;
}

void InputGenerator::replaceKeywords(QString &str,
                                     const Core::Molecule &mol) const
{
  // Find each coordinate block keyword in the file, then generate and replace
  // it with the appropriate values.
  QRegExp coordParser("\\$\\$coords:([^\\$]*)\\$\\$");
  int ind = 0;
  while ((ind = coordParser.indexIn(str, ind)) != -1) {
    // Extract spec and prepare the replacement
    const QString keyword = coordParser.cap(0);
    const QString spec = coordParser.cap(1);

    // Replace all blocks with this signature
    str.replace(keyword, generateCoordinateBlock(spec, mol));

  } // end for coordinate block
}

} // namespace QtPlugins
} // namespace Avogadro
