/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "scriptchargemodel.h"

#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/pythonscript.h>

// formats supported in scripts
#include <avogadro/io/cjsonformat.h>
#include <avogadro/io/cmlformat.h>
#include <avogadro/io/mdlformat.h>
#include <avogadro/io/pdbformat.h>
#include <avogadro/io/sdfformat.h>
#include <avogadro/io/xyzformat.h>

#include <QtCore/QDebug>
#include <QtCore/QScopedPointer>

#include <qjsonarray.h>
#include <qjsondocument.h>
#include <qjsonobject.h>
#include <qjsonvalue.h>

namespace Avogadro::QtPlugins {

ScriptChargeModel::ScriptChargeModel(const QString& scriptFileName_)
  : m_interpreter(new QtGui::PythonScript(scriptFileName_)),
    m_inputFormat(NotUsed), m_valid(false), m_partialCharges(false),
    m_electrostatics(false)
{
  m_elements.reset();
  readMetaData();
}

ScriptChargeModel::~ScriptChargeModel()
{
  delete m_interpreter;
}

void ScriptChargeModel::setPackageInfo(const QString& packageDir,
                                       const QString& command,
                                       const QString& identifier)
{
  m_interpreter->setPackageInfo(packageDir, command, identifier);
}

void ScriptChargeModel::readMetaData(const QVariantMap& metadata)
{
  resetMetaData();

  m_identifier = metadata.value("identifier").toString().toStdString();
  m_name = metadata.value("model-name").toString().toStdString();
  m_description = metadata.value("description").toString().toStdString();

  QString inputFmt = metadata.value("input-format").toString();
  m_inputFormat = stringToFormat(inputFmt.toStdString());
  m_formatString = inputFmt;

  QVariantMap support = metadata.value("support").toMap();
  m_partialCharges = support.value("charges", false).toBool();
  m_electrostatics = support.value("potentials", false).toBool();

  QString elemStr = support.value("elements").toString();
  if (!elemStr.isEmpty())
    processElementString(elemStr);

  m_valid =
    !m_identifier.empty() && !m_name.empty() && m_inputFormat != NotUsed;
}

QString ScriptChargeModel::scriptFilePath() const
{
  return m_interpreter->scriptFilePath();
}

Calc::ChargeModel* ScriptChargeModel::newInstance() const
{
  auto* copy = new ScriptChargeModel();
  if (m_interpreter->isPackageMode()) {
    copy->m_interpreter->setPackageInfo(m_interpreter->packageDir(),
                                        m_interpreter->packageCommand(),
                                        m_interpreter->packageIdentifier());
    copy->copyMetaDataFrom(*this);
  } else {
    copy->m_interpreter->setScriptFilePath(m_interpreter->scriptFilePath());
    copy->readMetaData();
  }
  return copy;
}

void ScriptChargeModel::copyMetaDataFrom(const ScriptChargeModel& other)
{
  m_identifier = other.m_identifier;
  m_name = other.m_name;
  m_description = other.m_description;
  m_inputFormat = other.m_inputFormat;
  m_formatString = other.m_formatString;
  m_partialCharges = other.m_partialCharges;
  m_electrostatics = other.m_electrostatics;
  m_elements = other.m_elements;
  m_valid = other.m_valid;
}

MatrixX ScriptChargeModel::partialCharges(const Core::Molecule& mol) const
{
  MatrixX charges(mol.atomCount(), 1);

  // check to see if we already have them in the molecule
  charges = mol.partialCharges(m_identifier);
  // if there's a non-zero charge, then we're done
  for (unsigned int i = 0; i < charges.rows(); ++i) {
    if (abs(charges(i, 0)) > 0.00001)
      return charges;
  }

  // Create the intermediate format writer
  std::string intermediate;
  QScopedPointer<Io::FileFormat> format(createFileFormat(m_inputFormat));

  if (format.isNull()) {
    appendError("Cannot create file format.");
    return charges;
  }

  if (!format->writeString(intermediate, mol)) {
    appendError(format->error(), false);
    return charges;
  }

  // Call the script to convert the file
  QByteArray result =
    m_interpreter->execute(QStringList() << "--charges", intermediate.c_str());

  if (m_interpreter->hasErrors()) {
    foreach (const QString& err, m_interpreter->errorList()) {
      appendError(err.toStdString());
    }

    return charges;
  }

  // parse the result - each charge should be on a line
  QString resultString = QString(result);
  QStringList lines = resultString.split('\n');
  // keep a separate atom counter in case there is other text
  // (e.g., "normal termination, etc.")
  unsigned int atom = 0;
  for (const auto& line : lines) {
    if (line.isEmpty())
      continue;

    bool ok;
    double charge = line.toDouble(&ok);
    if (!ok) {
      appendError("Invalid charge: " + line.toStdString());
      continue;
    }

    charges(atom, 0) = charge;
    ++atom;
  }
  return charges;
}

MatrixX ScriptChargeModel::partialCharges(Core::Molecule& mol) const
{
  // just create a copy of the const version
  MatrixX charges = partialCharges(static_cast<const Core::Molecule&>(mol));
  // cache them
  mol.setPartialCharges(m_identifier, charges);
  return charges;
}

double ScriptChargeModel::potential(Core::Molecule& mol,
                                    const Vector3& point) const
{
  // just create an array of size one and run that
  Core::Array<Vector3> points;
  points.push_back(point);

  Core::Array<double> results = potentials(mol, points);
  if (results.size() == 1)
    return results[0];
  else
    return 0.0;
}

Core::Array<double> ScriptChargeModel::potentials(
  Core::Molecule& mol, const Core::Array<Vector3>& points) const
{
  // first off, if the script doesn't handle potentials
  //   call the parent class (default method from partial charges)
  if (!m_electrostatics)
    return Calc::ChargeModel::potentials(mol, points);

  // Create the intermediate format writer
  std::string intermediate;
  QScopedPointer<Io::FileFormat> format(createFileFormat(m_inputFormat));
  Core::Array<double> potentials(points.size(), 0.0);

  if (format.isNull()) {
    appendError("Cannot create file format.");
    return potentials;
  }

  if (!format->writeString(intermediate, mol)) {
    appendError(format->error(), false);
    return potentials;
  }

  // now we stuff the file and the points into JSON
  QJsonObject json;
  json[m_formatString] = QString::fromStdString(intermediate);
  QJsonArray pointsArray;
  for (const auto& i : points) {
    QJsonArray point;
    point << i.x() << i.y() << i.z();
    pointsArray.append(point);
  }
  json["points"] = pointsArray;
  QJsonDocument doc(json);

  // Call the script to convert the file
  QByteArray result =
    m_interpreter->execute(QStringList() << "--potentials", doc.toJson());

  if (m_interpreter->hasErrors()) {
    foreach (const QString& err, m_interpreter->errorList())
      appendError(err.toStdString());
    return potentials;
  }

  // parse the result - each potential should be on a line
  QString resultString = QString(result);
  QStringList lines = resultString.split('\n');
  for (const QString& line : lines) {
    if (line.isEmpty())
      continue;

    bool ok;
    double potential = line.toDouble(&ok);
    if (!ok) {
      appendError("Invalid potential: " + line.toStdString());
      continue;
    }
    potentials.push_back(potential);
  }

  return potentials;
}

ScriptChargeModel::Format ScriptChargeModel::stringToFormat(
  const std::string& str)
{
  if (str == "cjson")
    return Cjson;
  else if (str == "cml")
    return Cml;
  else if (str == "mdl" || str == "mol")
    return Mdl;
  else if (str == "sdf")
    return Sdf;
  else if (str == "pdb")
    return Pdb;
  else if (str == "xyz")
    return Xyz;
  return NotUsed;
}

Io::FileFormat* ScriptChargeModel::createFileFormat(
  ScriptChargeModel::Format fmt)
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

void ScriptChargeModel::resetMetaData()
{
  m_valid = false;
  m_partialCharges = false;
  m_electrostatics = false;
  m_inputFormat = NotUsed;
  m_identifier.clear();
  m_name.clear();
  m_description.clear();
  m_formatString.clear();
}

void ScriptChargeModel::readMetaData()
{
  resetMetaData();

  QByteArray output(m_interpreter->execute(QStringList() << "--metadata"));

  if (m_interpreter->hasErrors()) {
    qWarning() << "Error retrieving metadata for charge script:"
               << scriptFilePath() << "\n"
               << m_interpreter->errorList();
    return;
  }

  QJsonParseError parseError;
  QJsonDocument doc(QJsonDocument::fromJson(output, &parseError));
  if (parseError.error != QJsonParseError::NoError) {
    qWarning() << "Error parsing metadata for charge script:"
               << scriptFilePath() << "\n"
               << parseError.errorString() << "(at offset" << parseError.offset
               << ")";
    return;
  }

  if (!doc.isObject()) {
    qWarning() << "Error parsing metadata for charge script:"
               << scriptFilePath() << "\nResult is not a JSON object:\n"
               << output;
    return;
  }

  const QJsonObject metaData(doc.object());

  // Read required inputs first.
  std::string identifierTmp;
  if (!parseString(metaData, "identifier", identifierTmp)) {
    qWarning() << "Error parsing metadata for charge script:"
               << scriptFilePath() << "\n"
               << "Error parsing required member 'identifier'"
               << "\n"
               << output;
    return;
  }
  m_identifier = identifierTmp;

  std::string nameTmp;
  if (!parseString(metaData, "name", nameTmp)) {
    qWarning() << "Error parsing metadata for charge script:"
               << scriptFilePath() << "\n"
               << "Error parsing required member 'name'"
               << "\n"
               << output;
    return;
  }
  m_name = nameTmp;

  std::string descriptionTmp;
  parseString(metaData, "description", descriptionTmp);
  m_description = descriptionTmp; // optional

  Format inputFormatTmp = NotUsed;
  std::string inputFormatStrTmp;
  if (!parseString(metaData, "inputFormat", inputFormatStrTmp)) {
    qWarning() << "Error parsing metadata for charge script:"
               << scriptFilePath() << "\n"
               << "Member 'inputFormat' required for writable formats."
               << "\n"
               << output;
    return;
  }
  m_formatString = inputFormatStrTmp.c_str(); // for the json key

  // Validate the input format
  inputFormatTmp = stringToFormat(inputFormatStrTmp);
  if (inputFormatTmp == NotUsed) {
    qWarning() << "Error parsing metadata for charge script:"
               << scriptFilePath() << "\n"
               << "Member 'inputFormat' not recognized:"
               << inputFormatStrTmp.c_str()
               << "\nValid values are cjson, cml, mdl/sdf, pdb, or xyz.\n"
               << output;
    return;
  }
  m_inputFormat = inputFormatTmp;

  // check if we handle charges and/or potentials
  if (!metaData["charges"].isBool()) {
    return; // not valid
  }
  m_partialCharges = metaData["charges"].toBool();
  if (!metaData["potential"].isBool()) {
    return; // not valid
  }
  m_electrostatics = metaData["potential"].toBool();

  // get the element mask
  // (if it doesn't exist, the default is no elements anyway)
  m_valid = parseElements(metaData);
}

bool ScriptChargeModel::parseString(const QJsonObject& ob, const QString& key,
                                    std::string& str)
{
  if (!ob[key].isString())
    return false;

  str = ob[key].toString().toStdString();

  return !str.empty();
}

void ScriptChargeModel::processElementString(const QString& str)
{
  // parse the QString
  // first turn any commas into whitespace
  QString str2(str);
  str2.replace(',', ' ');
  // then split on whitespace
  QStringList strList =
    str2.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
  foreach (QString sstr, strList) {
    // these should be numbers or ranges (e.g., 1-84)
    if (sstr.contains('-')) {
      // range, so split on the dash
      QStringList strList2 = sstr.split('-');
      if (strList2.size() != 2)
        return;

      // get the two numbers
      bool ok;
      int start = strList2[0].toInt(&ok);
      if (!ok || start < 1 || start > 119)
        return;
      int end = strList2[1].toInt(&ok);
      if (!ok || end < 1 || end > 119)
        return;
      for (int i = start; i <= end; ++i)
        m_elements.set(i);
    }

    bool ok;
    int i = sstr.toInt(&ok);
    if (!ok || i < 1 || i > 119)
      return;

    m_elements.set(i);
  }
}

bool ScriptChargeModel::parseElements(const QJsonObject& ob)
{
  m_elements.reset();

  // we could either get a string or an array (of numbers)
  if (ob["elements"].isString()) {
    auto str = ob["elements"].toString();
    processElementString(str);

  } else if (ob["elements"].isArray()) {
    QJsonArray arr = ob["elements"].toArray();
    for (auto&& i : arr) {
      if (i.isString()) {
        processElementString(i.toString());
      } else if (i.isDouble()) {
        int element = i.toInt();
        if (element >= 1 && element <= 119) // check the range
          m_elements.set(element);
      }
    }
  }
  return true;
}

} // namespace Avogadro::QtPlugins
