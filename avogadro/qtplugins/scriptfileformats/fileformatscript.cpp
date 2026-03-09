/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "fileformatscript.h"

#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/pythonscript.h>

#include <avogadro/io/cjsonformat.h>
#include <avogadro/io/cmlformat.h>
#include <avogadro/io/mdlformat.h>
#include <avogadro/io/pdbformat.h>
#include <avogadro/io/sdfformat.h>
#include <avogadro/io/xyzformat.h>

#include <QtCore/QDebug>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QScopedPointer>

namespace Avogadro::QtPlugins {

FileFormatScript::FileFormatScript(const QString& scriptFileName_)
  : m_interpreter(new QtGui::PythonScript(scriptFileName_)), m_valid(false),
    m_bondOnRead(false), m_fileModeRead(false), m_fileModeWrite(false),
    m_inputFormat(NotUsed), m_outputFormat(NotUsed)
{
}

FileFormatScript::~FileFormatScript()
{
  delete m_interpreter;
}

void FileFormatScript::setPackageInfo(const QString& packageDir,
                                      const QString& command,
                                      const QString& identifier)
{
  m_interpreter->setPackageInfo(packageDir, command, identifier);
}

void FileFormatScript::readMetaData(const QVariantMap& metadata)
{
  resetMetaData();

  m_identifier = metadata.value("identifier").toString().toStdString();
  if (!m_identifier.empty())
    m_identifier = "User Script: " + m_identifier;

  m_name = metadata.value("format-name").toString().toStdString();
  m_description = metadata.value("description").toString().toStdString();

  QVariantMap support = metadata.value("support").toMap();
  if (support.value("read", false).toBool())
    m_operations |= Io::FileFormat::Read;
  if (support.value("write", false).toBool())
    m_operations |= Io::FileFormat::Write;
  // Parse file-mode: "read", "write", or ["read", "write"]
  if (metadata.contains("file-mode")) {
    QVariant fileModeVar = metadata.value("file-mode");
    QStringList fileModes;
    if (fileModeVar.type() == QVariant::List) {
      for (const auto& v : fileModeVar.toList())
        fileModes << v.toString();
    } else {
      fileModes << fileModeVar.toString();
    }
    m_fileModeRead = fileModes.contains("read");
    m_fileModeWrite = fileModes.contains("write");
  }

  if (m_fileModeRead || m_fileModeWrite)
    m_operations |= Io::FileFormat::File;
  else
    m_operations |=
      Io::FileFormat::File | Io::FileFormat::Stream | Io::FileFormat::String;

  if (m_operations & Io::FileFormat::Write) {
    QString inputFmt = metadata.value("input-format").toString();
    m_inputFormat = stringToFormat(inputFmt.toStdString());
  }

  if (m_operations & Io::FileFormat::Read) {
    QString outputFmt = metadata.value("output-format").toString();
    m_outputFormat = stringToFormat(outputFmt.toStdString());
  }

  // Parse file extensions array
  QVariantList extList = metadata.value("file-extensions").toList();
  for (const auto& ext : extList)
    m_fileExtensions.push_back(ext.toString().toStdString());

  // Parse mime types array
  QVariantList mimeList = metadata.value("mime-types").toList();
  for (const auto& mime : mimeList)
    m_mimeTypes.push_back(mime.toString().toStdString());

  // Check for bond-on-read
  if (metadata.contains("bond"))
    m_bondOnRead = metadata.value("bond").toBool();

  m_valid =
    !m_identifier.empty() && !m_name.empty() &&
    (!(m_operations & Io::FileFormat::Write) || m_inputFormat != NotUsed) &&
    (!(m_operations & Io::FileFormat::Read) || m_outputFormat != NotUsed);
}

QString FileFormatScript::scriptFilePath() const
{
  return m_interpreter->scriptFilePath();
}

Io::FileFormat* FileFormatScript::newInstance() const
{
  auto* copy = new FileFormatScript();
  copy->m_interpreter->setPackageInfo(m_interpreter->packageDir(),
                                      m_interpreter->packageCommand(),
                                      m_interpreter->packageIdentifier());
  copy->copyMetaDataFrom(*this);
  return copy;
}

void FileFormatScript::copyMetaDataFrom(const FileFormatScript& other)
{
  m_identifier = other.m_identifier;
  m_name = other.m_name;
  m_description = other.m_description;
  m_specificationUrl = other.m_specificationUrl;
  m_operations = other.m_operations;
  m_inputFormat = other.m_inputFormat;
  m_outputFormat = other.m_outputFormat;
  m_fileExtensions = other.m_fileExtensions;
  m_mimeTypes = other.m_mimeTypes;
  m_bondOnRead = other.m_bondOnRead;
  m_fileModeRead = other.m_fileModeRead;
  m_fileModeWrite = other.m_fileModeWrite;
  m_valid = other.m_valid;
}

bool FileFormatScript::read(std::istream& in, Core::Molecule& molecule)
{
  if (m_fileModeRead) {
    appendError("This format requires a file path and cannot be read from a "
                "stream.");
    return false;
  }

  // Create intermediate format reader
  QScopedPointer<FileFormat> format(createFileFormat(m_outputFormat));

  if (format.isNull()) {
    appendError("Invalid intermediate format enum value.");
    return false;
  }

  // Copy input into memory
  /// @todo would be nice to pass the stream to the interpreter directly...
  // Get length first:
  in.seekg(0, std::istream::end);
  std::istream::pos_type size = in.tellg();

  // Construct byte array
  QByteArray buffer;
  buffer.resize(static_cast<int>(size));
  in.seekg(0, std::istream::beg);
  in.read(buffer.data(), size);

  // Call the script to convert the file
  QByteArray result = m_interpreter->execute(QStringList() << "--read", buffer);

  if (m_interpreter->hasErrors()) {
    foreach (const QString& err, m_interpreter->errorList())
      appendError(err.toStdString());
    return false;
  }

  if (!format->readString(std::string(result.constData(), result.size()),
                          molecule)) {
    appendError(format->error(), false);
    return false;
  }

  if (m_bondOnRead) {
    molecule.perceiveBondsSimple();
    molecule.perceiveBondOrders();
  }

  return true;
}

bool FileFormatScript::write(std::ostream& out, const Core::Molecule& molecule)
{
  if (m_fileModeWrite) {
    appendError("This format requires a file path and cannot be written to a "
                "stream.");
    return false;
  }

  // Create the intermediate format writer
  std::string intermediate;
  QScopedPointer<FileFormat> format(createFileFormat(m_inputFormat));

  if (format.isNull()) {
    appendError("Invalid intermediate format enum value.");
    return false;
  }

  if (!format->writeString(intermediate, molecule)) {
    appendError(format->error(), false);
    return false;
  }

  // Call the script to convert the file
  QByteArray result = m_interpreter->execute(
    QStringList() << "--write",
    QByteArray::fromRawData(intermediate.c_str(), intermediate.size()));

  if (m_interpreter->hasErrors()) {
    foreach (const QString& err, m_interpreter->errorList())
      appendError(err.toStdString());
    return false;
  }

  out.write(result.constData(), result.size());

  return true;
}

FileFormatScript::Format FileFormatScript::stringToFormat(
  const std::string& str)
{
  if (str == "cjson")
    return Cjson;
  else if (str == "cml")
    return Cml;
  else if (str == "mdl" || str == "mol")
    return Mdl;
  else if (str == "pdb")
    return Pdb;
  else if (str == "sdf")
    return Sdf;
  else if (str == "xyz")
    return Xyz;
  return NotUsed;
}

std::string FileFormatScript::formatToString(Format fmt)
{
  switch (fmt) {
    case Cjson:
      return "cjson";
    case Cml:
      return "cml";
    case Mdl:
      return "mdl";
    case Pdb:
      return "pdb";
    case Sdf:
      return "sdf";
    case Xyz:
      return "xyz";
    default:
      return "";
  }
}

bool FileFormatScript::readFile(const std::string& fileName,
                                Core::Molecule& molecule)
{
  if (!m_fileModeRead)
    return FileFormat::readFile(fileName, molecule);

  QScopedPointer<FileFormat> format(createFileFormat(m_outputFormat));
  if (format.isNull()) {
    appendError("Invalid intermediate format enum value.");
    return false;
  }

  QJsonObject payload;
  payload["operation"] = QLatin1String("read");
  payload["filename"] = QString::fromStdString(fileName);
  QByteArray input = QJsonDocument(payload).toJson(QJsonDocument::Compact);

  QByteArray result = m_interpreter->execute(QStringList() << "--read", input);

  if (m_interpreter->hasErrors()) {
    foreach (const QString& err, m_interpreter->errorList())
      appendError(err.toStdString());
    return false;
  }

  if (!format->readString(std::string(result.constData(), result.size()),
                          molecule)) {
    appendError(format->error(), false);
    return false;
  }

  if (m_bondOnRead) {
    molecule.perceiveBondsSimple();
    molecule.perceiveBondOrders();
  }

  return true;
}

bool FileFormatScript::writeFile(const std::string& fileName,
                                 const Core::Molecule& molecule)
{
  if (!m_fileModeWrite)
    return FileFormat::writeFile(fileName, molecule);

  QScopedPointer<FileFormat> format(createFileFormat(m_inputFormat));
  if (format.isNull()) {
    appendError("Invalid intermediate format enum value.");
    return false;
  }

  std::string intermediate;
  if (!format->writeString(intermediate, molecule)) {
    appendError(format->error(), false);
    return false;
  }

  QJsonObject payload;
  payload["operation"] = QLatin1String("write");
  payload["filename"] = QString::fromStdString(fileName);
  payload[QString::fromStdString(formatToString(m_inputFormat))] =
    QString::fromStdString(intermediate);
  QByteArray input = QJsonDocument(payload).toJson(QJsonDocument::Compact);

  m_interpreter->execute(QStringList() << "--write", input);

  if (m_interpreter->hasErrors()) {
    foreach (const QString& err, m_interpreter->errorList())
      appendError(err.toStdString());
    return false;
  }

  return true;
}

Io::FileFormat* FileFormatScript::createFileFormat(FileFormatScript::Format fmt)
{
  switch (fmt) {
    case Cjson:
      return new Io::CjsonFormat;
    case Cml:
      return new Io::CmlFormat;
    case Mdl:
      return new Io::MdlFormat;
    case Pdb:
      return new Io::PdbFormat;
    case Sdf:
      return new Io::SdfFormat;
    case Xyz:
      return new Io::XyzFormat;
    default:
    case NotUsed:
      return nullptr;
  }
}

void FileFormatScript::resetMetaData()
{
  m_operations = Io::FileFormat::None;
  m_valid = false;
  m_bondOnRead = false;
  m_fileModeRead = false;
  m_fileModeWrite = false;
  m_inputFormat = NotUsed;
  m_identifier.clear();
  m_name.clear();
  m_description.clear();
  m_specificationUrl.clear();
  m_fileExtensions.clear();
  m_mimeTypes.clear();
}

} // namespace Avogadro::QtPlugins
