/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "scriptenergy.h"

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
#include <QtCore/QDir>
#include <QtCore/QScopedPointer>

#include <QRegularExpression>

#include <qjsonarray.h>
#include <qjsondocument.h>
#include <qjsonobject.h>
#include <qjsonvalue.h>

namespace Avogadro::QtPlugins {

ScriptEnergy::ScriptEnergy(const QString& scriptFileName_)
  : m_interpreter(new QtGui::PythonScript(scriptFileName_)),
    m_inputFormat(NotUsed), m_valid(true), m_gradients(false), m_ions(false),
    m_radicals(false), m_unitCells(false)
{
  m_elements.reset();
  readMetaData();
}

ScriptEnergy::~ScriptEnergy()
{
  delete m_interpreter;
}

void ScriptEnergy::setPackageInfo(const QString& packageDir,
                                  const QString& command,
                                  const QString& identifier)
{
  m_interpreter->setPackageInfo(packageDir, command, identifier);
}

void ScriptEnergy::readMetaData(const QVariantMap& metadata)
{
  resetMetaData();

  m_identifier = metadata.value("identifier").toString().toStdString();
  m_name = metadata.value("model-name").toString().toStdString();
  m_description = metadata.value("description").toString().toStdString();

  QString inputFmt = metadata.value("input-format").toString();
  m_inputFormat = stringToFormat(inputFmt.toStdString());
  m_formatString = inputFmt;

  QVariantMap support = metadata.value("support").toMap();
  m_gradients = support.value("gradients", false).toBool();
  m_unitCells = support.value("unit-cell", false).toBool();
  m_ions = support.value("ions", false).toBool();
  m_radicals = support.value("radicals", false).toBool();

  QString elemStr = support.value("elements").toString();
  if (!elemStr.isEmpty())
    processElementString(elemStr);

  m_valid =
    !m_identifier.empty() && !m_name.empty() && m_inputFormat != NotUsed;
}

QString ScriptEnergy::scriptFilePath() const
{
  return m_interpreter->scriptFilePath();
}

Calc::EnergyCalculator* ScriptEnergy::newInstance() const
{
  auto* copy = new ScriptEnergy();
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

void ScriptEnergy::copyMetaDataFrom(const ScriptEnergy& other)
{
  m_identifier = other.m_identifier;
  m_name = other.m_name;
  m_description = other.m_description;
  m_inputFormat = other.m_inputFormat;
  m_formatString = other.m_formatString;
  m_gradients = other.m_gradients;
  m_unitCells = other.m_unitCells;
  m_ions = other.m_ions;
  m_radicals = other.m_radicals;
  m_elements = other.m_elements;
  m_valid = other.m_valid;
}

void ScriptEnergy::setMolecule(Core::Molecule* mol)
{
  m_molecule = mol;

  // should check if the molecule is valid for this script
  // .. this should never happen, but let's be defensive
  if (mol == nullptr || m_interpreter == nullptr) {
    return; // nothing to do
  }

  if (!m_unitCells && mol->unitCell()) {
    // appendError("Unit cell not supported for this script.");
    return;
  }
  if (!m_ions && mol->totalCharge() != 0) {
    // appendError("Ionized molecules not supported for this script.");
    return;
  }
  if (!m_radicals && mol->totalSpinMultiplicity() != 1) {
    // appendError("Radical molecules not supported for this script.");
    return;
  }

  // start the process
  // we need a tempory file to write the molecule
  QScopedPointer<Io::FileFormat> format(createFileFormat(m_inputFormat));
  if (format.isNull()) {
    // appendError("Invalid input format.");
    return;
  }
  // get a temporary filename
  QString tempPath = QDir::tempPath();
  if (!tempPath.endsWith(QDir::separator()))
    tempPath += QDir::separator();
  QString tempPattern =
    tempPath + "avogadroenergyXXXXXX." + format->fileExtensions()[0].c_str();
  m_tempFile.setFileTemplate(tempPattern);
  if (!m_tempFile.open()) {
    // appendError("Error creating temporary file.");
    return;
  }

  // write the molecule
  format->writeFile(m_tempFile.fileName().toStdString(), *mol);
  m_tempFile.close();

  // construct the command line options
  QStringList options;
  options << "-f" << m_tempFile.fileName();

  // if there was a previous process, kill it
  m_interpreter->asyncTerminate();
  // start the interpreter
  m_interpreter->asyncExecute(options);
}

Real ScriptEnergy::value(const Eigen::VectorXd& x)
{
  if (m_molecule == nullptr || m_interpreter == nullptr)
    return 0.0; // nothing to do

  // write the new coordinates and read the energy
  QByteArray input;
  for (Eigen::Index i = 0; i < x.size(); i += 3) {
    // write as x y z (space separated)
    input += QString::number(x[i]).toUtf8() + " " +
             QString::number(x[i + 1]).toUtf8() + " " +
             QString::number(x[i + 2]).toUtf8() + "\n";
  }
  // qDebug() << " wrote coords ";
  QByteArray result = m_interpreter->asyncWriteAndResponse(input);
  // qDebug() << " got result " << result;

  // go through lines in result until we see "AvogadroEnergy: "
  QStringList lines = QString(result).remove('\r').split('\n');
  double energy = 0.0;
  for (auto line : lines) {
    if (line.startsWith("AvogadroEnergy:")) {
      QStringList items = line.split(" ", Qt::SkipEmptyParts);
      if (items.size() > 1) {
        energy = items[1].toDouble();
        break;
      }
    }
  }

  energy += constraintEnergies(x);
  return energy; // if conversion fails, returns 0.0
}

void ScriptEnergy::gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_gradients) {
    EnergyCalculator::gradient(x, grad);
    return;
  }

  // Get the gradient from the script
  // write the new coordinates and read the energy
  QByteArray input;
  for (Eigen::Index i = 0; i < x.size(); i += 3) {
    // write as x y z (space separated)
    input += QString::number(x[i]).toUtf8() + " " +
             QString::number(x[i + 1]).toUtf8() + " " +
             QString::number(x[i + 2]).toUtf8() + "\n";
  }
  QByteArray result = m_interpreter->asyncWriteAndResponse(input);

  // parse the result
  // first split on newlines
  QStringList lines = QString(result).remove('\r').split('\n');
  unsigned int i = 0;
  bool readingGrad = false;
  for (auto line : lines) {
    if (line.startsWith("AvogadroGradient:")) {
      readingGrad = true;
      continue; // next line
    }

    if (readingGrad) {
      QStringList items = line.split(" ", Qt::SkipEmptyParts);
      if (items.size() == 3) {
        grad[i] = items[0].toDouble();
        grad[i + 1] = items[1].toDouble();
        grad[i + 2] = items[2].toDouble();
        i += 3;
      }

      if (i > x.size())
        break;
    }
  }

  cleanGradients(grad);
  constraintGradients(x, grad);
}

ScriptEnergy::Format ScriptEnergy::stringToFormat(const std::string& str)
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

Io::FileFormat* ScriptEnergy::createFileFormat(ScriptEnergy::Format fmt)
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

void ScriptEnergy::resetMetaData()
{
  m_valid = false;
  m_gradients = false;
  m_ions = false;
  m_radicals = false;
  m_unitCells = false;
  m_inputFormat = NotUsed;
  m_identifier.clear();
  m_name.clear();
  m_description.clear();
  m_formatString.clear();
  m_elements.reset();
}

void ScriptEnergy::readMetaData()
{
  resetMetaData();

  QByteArray output(m_interpreter->execute(QStringList() << "--metadata"));

  if (m_interpreter->hasErrors()) {
    qWarning() << tr("Error retrieving metadata for energy script: %1")
                    .arg(scriptFilePath())
               << "\n"
               << m_interpreter->errorList();
    return;
  }

  QJsonParseError parseError;
  QJsonDocument doc(QJsonDocument::fromJson(output, &parseError));
  if (parseError.error != QJsonParseError::NoError) {
    qWarning() << tr("Error parsing metadata for energy script: %1")
                    .arg(scriptFilePath())
               << "\n"
               << parseError.errorString();
    return;
  }

  if (!doc.isObject()) {
    qWarning() << tr("Error parsing metadata for energy script: %1\n"
                     "Result is not a JSON object.\n")
                    .arg(scriptFilePath());
    return;
  }

  const QJsonObject metaData(doc.object());

  // Read required inputs first.
  std::string identifierTmp;
  if (!parseString(metaData, "identifier", identifierTmp)) {
    qWarning() << "Error parsing metadata for energy script:"
               << scriptFilePath() << "\n"
               << "Error parsing required member 'identifier'"
               << "\n"
               << output;
    return;
  }
  m_identifier = identifierTmp;

  std::string nameTmp;
  if (!parseString(metaData, "name", nameTmp)) {
    qWarning() << "Error parsing metadata for energy script:"
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
    qWarning() << "Error parsing metadata for energy script:"
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
    qWarning() << "Error parsing metadata for energy script:"
               << scriptFilePath() << "\n"
               << "Member 'inputFormat' not recognized:"
               << inputFormatStrTmp.c_str()
               << "\nValid values are cjson, cml, mdl/sdf, pdb, or xyz.\n"
               << output;
    return;
  }
  m_inputFormat = inputFormatTmp;

  // check ions, radicals, unit cells
  /* e.g.,
        "unitCell": False,
        "gradients": True,
        "ion": False,
        "radical": False,
  */
  if (!metaData["gradients"].isBool()) {
    return; // not valid
  }
  m_gradients = metaData["gradients"].toBool();

  if (!metaData["unitCell"].isBool()) {
    return; // not valid
  }
  m_unitCells = metaData["unitCell"].toBool();

  if (!metaData["ion"].isBool()) {
    return; // not valid
  }
  m_ions = metaData["ion"].toBool();

  if (!metaData["radical"].isBool()) {
    return; // not valid
  }
  m_radicals = metaData["radical"].toBool();

  // get the element mask
  // (if it doesn't exist, the default is no elements anyway)
  m_valid = parseElements(metaData);
}

bool ScriptEnergy::parseString(const QJsonObject& ob, const QString& key,
                               std::string& str)
{
  if (!ob[key].isString())
    return false;

  str = ob[key].toString().toStdString();

  return !str.empty();
}

void ScriptEnergy::processElementString(const QString& str)
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

bool ScriptEnergy::parseElements(const QJsonObject& object)
{
  m_elements.reset();

  // we could either get a string or an array (of numbers)
  if (object["elements"].isString()) {
    auto str = object["elements"].toString();
    processElementString(str);

  } else if (object["elements"].isArray()) {
    QJsonArray arr = object["elements"].toArray();
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
