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
#include <avogadro/io/xyzformat.h>

#include <QtCore/QDebug>
#include <QtCore/QScopedPointer>

#include <qjsonarray.h>
#include <qjsondocument.h>
#include <qjsonobject.h>
#include <qjsonvalue.h>

namespace Avogadro {
namespace QtPlugins {

FileFormatScript::FileFormatScript(const QString& scriptFileName_)
  : m_interpreter(new QtGui::PythonScript(scriptFileName_)), m_valid(false),
    m_bondOnRead(false), m_inputFormat(NotUsed), m_outputFormat(NotUsed)
{
  readMetaData();
}

FileFormatScript::~FileFormatScript()
{
  delete m_interpreter;
}

QString FileFormatScript::scriptFilePath() const
{
  return m_interpreter->scriptFilePath();
}

Io::FileFormat* FileFormatScript::newInstance() const
{
  return new FileFormatScript(m_interpreter->scriptFilePath());
}

bool FileFormatScript::read(std::istream& in, Core::Molecule& molecule)
{
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
  }

  return true;
}

bool FileFormatScript::write(std::ostream& out, const Core::Molecule& molecule)
{
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
  else if (str == "mdl" || str == "mol" || str == "sdf" || str == "sd")
    return Mdl;
  else if (str == "pdb")
    return Pdb;
  else if (str == "xyz")
    return Xyz;
  return NotUsed;
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
  m_inputFormat = NotUsed;
  m_identifier.clear();
  m_name.clear();
  m_description.clear();
  m_specificationUrl.clear();
  m_fileExtensions.clear();
  m_mimeTypes.clear();
}

void FileFormatScript::readMetaData()
{
  resetMetaData();

  QByteArray output(m_interpreter->execute(QStringList() << "--metadata"));

  if (m_interpreter->hasErrors()) {
    qWarning() << "Error retrieving metadata for file format script:"
               << scriptFilePath() << "\n"
               << m_interpreter->errorList();
    return;
  }

  QJsonParseError parseError;
  QJsonDocument doc(QJsonDocument::fromJson(output, &parseError));
  if (parseError.error != QJsonParseError::NoError) {
    qWarning() << "Error parsing metadata for file format script:"
               << scriptFilePath() << "\n"
               << parseError.errorString() << "(at offset" << parseError.offset
               << ")";
    return;
  }

  if (!doc.isObject()) {
    qWarning() << "Error parsing metadata for file format script:"
               << scriptFilePath() << "\nResult is not a JSON object:\n"
               << output;
    return;
  }

  const QJsonObject metaData(doc.object());

  // Read required inputs first.
  std::vector<std::string> opStringsTmp;
  if (!parseStringArray(metaData, "operations", opStringsTmp)) {
    qWarning() << "Error parsing metadata for file format script:"
               << scriptFilePath() << "\n"
               << "Error parsing required member 'operations'"
               << "\n"
               << output;
    return;
  }

  // validate operations:
  Operations operationsTmp = Io::FileFormat::None;
  typedef std::vector<std::string>::const_iterator StringVectorIter;
  for (StringVectorIter it = opStringsTmp.begin(), itEnd = opStringsTmp.end();
       it != itEnd; ++it) {
    if (*it == "read")
      operationsTmp |= Io::FileFormat::Read;
    else if (*it == "write")
      operationsTmp |= Io::FileFormat::Write;
    else {
      qWarning() << "Error parsing metadata for file format script:"
                 << scriptFilePath() << "\n"
                 << "Unrecognized operation:" << it->c_str() << "\n"
                 << output;
      return;
    }
  }

  std::string identifierTmp;
  if (!parseString(metaData, "identifier", identifierTmp)) {
    qWarning() << "Error parsing metadata for file format script:"
               << scriptFilePath() << "\n"
               << "Error parsing required member 'operations'"
               << "\n"
               << output;
    return;
  }

  std::string nameTmp;
  if (!parseString(metaData, "name", nameTmp)) {
    qWarning() << "Error parsing metadata for file format script:"
               << scriptFilePath() << "\n"
               << "Error parsing required member 'name'"
               << "\n"
               << output;
    return;
  }

  // input format is required if write operations are supported:
  Format inputFormatTmp = NotUsed;
  if (operationsTmp & Io::FileFormat::Write) {
    std::string inputFormatStrTmp;
    if (!parseString(metaData, "inputFormat", inputFormatStrTmp)) {
      qWarning() << "Error parsing metadata for file format script:"
                 << scriptFilePath() << "\n"
                 << "Member 'inputFormat' required for writable formats."
                 << "\n"
                 << output;
      return;
    }

    // Validate the input format
    inputFormatTmp = stringToFormat(inputFormatStrTmp);
    if (inputFormatTmp == NotUsed) {
      qWarning() << "Error parsing metadata for file format script:"
                 << scriptFilePath() << "\n"
                 << "Member 'inputFormat' not recognized:"
                 << inputFormatStrTmp.c_str()
                 << "\nValid values are cjson, cml, mdl/sdf, pdb, or xyz.\n"
                 << output;
      return;
    }
  }

  // output format is required if read operations are supported:
  Format outputFormatTmp = NotUsed;
  if (operationsTmp & Io::FileFormat::Read) {
    std::string outputFormatStrTmp;
    if (!parseString(metaData, "outputFormat", outputFormatStrTmp)) {
      qWarning() << "Error parsing metadata for file format script:"
                 << scriptFilePath() << "\n"
                 << "Member 'outputFormat' required for readable formats."
                 << "\n"
                 << output;
      return;
    }

    // Validate the output format
    outputFormatTmp = stringToFormat(outputFormatStrTmp);
    if (outputFormatTmp == NotUsed) {
      qWarning() << "Error parsing metadata for file format script:"
                 << scriptFilePath() << "\n"
                 << "Member 'outputFormat' not recognized:"
                 << outputFormatStrTmp.c_str()
                 << "\nValid values are cjson, cml, mdl/sdf, pdb, or xyz.\n"
                 << output;
      return;
    }
  }

  // If all required data is present, go ahead and set the member vars:
  m_operations = operationsTmp | Io::FileFormat::File | Io::FileFormat::Stream |
                 Io::FileFormat::String;
  m_inputFormat = inputFormatTmp;
  m_outputFormat = outputFormatTmp;
  m_identifier = std::string("User Script: ") + identifierTmp;
  m_name = nameTmp;

  // check if we should bond on read:
  if (metaData["bond"].isBool()) {
    m_bondOnRead = metaData["bond"].toBool();
  }

  // Everything else is optional:
  parseString(metaData, "description", m_description);
  parseString(metaData, "specificationUrl", m_specificationUrl);
  parseStringArray(metaData, "fileExtensions", m_fileExtensions);
  parseStringArray(metaData, "mimeTypes", m_mimeTypes);
  m_valid = true;
}

bool FileFormatScript::parseString(const QJsonObject& ob, const QString& key,
                                   std::string& str)
{
  if (!ob[key].isString())
    return false;

  str = ob[key].toString().toStdString();

  return !str.empty();
}

bool FileFormatScript::parseStringArray(const QJsonObject& ob,
                                        const QString& key,
                                        std::vector<std::string>& array)
{
  array.clear();

  if (!ob[key].isArray())
    return false;

  foreach (const QJsonValue& val, ob[key].toArray()) {
    if (!val.isString())
      return false;

    array.push_back(val.toString().toStdString());

    if (array.back().empty())
      return false;
  }

  return !array.empty();
}

} // namespace QtPlugins
} // namespace Avogadro
