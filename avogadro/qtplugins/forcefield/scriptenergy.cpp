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
#include <QtCore/QElapsedTimer>
#include <QtCore/QScopedPointer>
#include <QtCore/QSysInfo>
#include <QtCore/QtEndian>

#include <QRegularExpression>

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <limits>

#include <qjsonarray.h>
#include <qjsondocument.h>
#include <qjsonobject.h>
#include <qjsonvalue.h>

namespace Avogadro::QtPlugins {

namespace {

constexpr int BINARY_HEADER_SIZE = 16;
constexpr char BINARY_MAGIC[4] = { 'A', 'V', 'B', '1' };
constexpr quint16 BINARY_VERSION = 1;

constexpr quint16 FLAG_RESPONSE_ERROR = 0x8000;
constexpr quint16 FLAG_REQUEST_GRADIENT = 0x0001;

void appendFloat64LE(QByteArray& out, double value)
{
  quint64 bits = 0;
  static_assert(sizeof(bits) == sizeof(value), "Unexpected double size");
  std::memcpy(&bits, &value, sizeof(value));
  bits = qToLittleEndian(bits);
  out.append(reinterpret_cast<const char*>(&bits), sizeof(bits));
}

bool readFloat64LE(const char* src, const char* end, double& value)
{
  if (end - src < static_cast<ptrdiff_t>(sizeof(quint64)))
    return false;

  quint64 bits = 0;
  std::memcpy(&bits, src, sizeof(bits));
  bits = qFromLittleEndian(bits);
  std::memcpy(&value, &bits, sizeof(value));
  return true;
}

void appendFloatText(QByteArray& out, double value)
{
  out.append(QByteArray::number(value, 'g', 17));
}

bool readFloatText(const char*& pos, const char* end, double& value)
{
  if (pos == nullptr || pos >= end)
    return false;

  char* parsedEnd = nullptr;
  value = std::strtod(pos, &parsedEnd);
  if (parsedEnd == pos || parsedEnd == nullptr || parsedEnd > end)
    return false;

  pos = parsedEnd;
  return true;
}

} // namespace

ScriptEnergy::ScriptEnergy(const QString& scriptFileName_)
  : m_interpreter(new QtGui::PythonScript(scriptFileName_)),
    m_inputFormat(NotUsed), m_protocol(Protocol::TextV1), m_molecule(nullptr),
    m_valid(true), m_gradients(false), m_ions(false), m_radicals(false),
    m_unitCells(false)
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

  QString protocol = metadata.value("protocol").toString();
  m_protocol = stringToProtocol(protocol.toStdString());

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
  m_protocol = other.m_protocol;
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

  // Always reset the running server before validating/restarting.
  m_interpreter->asyncTerminate();

  if (!m_unitCells && mol->unitCell()) {
    appendError("Unit cell not supported for this script.");
    return;
  }
  if (!m_ions && mol->totalCharge() != 0) {
    appendError("Ionized molecules not supported for this script.");
    return;
  }
  if (!m_radicals && mol->totalSpinMultiplicity() != 1) {
    appendError("Radical molecules not supported for this script.");
    return;
  }

  // start the process
  // we need a tempory file to write the molecule
  QScopedPointer<Io::FileFormat> format(createFileFormat(m_inputFormat));
  if (format.isNull()) {
    appendError("Invalid input format.");
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
    appendError("Error creating temporary file.");
    return;
  }

  // write the molecule
  format->writeFile(m_tempFile.fileName().toStdString(), *mol);
  m_tempFile.close();

  // construct the command line options
  QStringList options;
  options << "-f" << m_tempFile.fileName();
  if (m_protocol == Protocol::BinaryV1)
    options << "--protocol"
            << "binary-v1";

  // start the interpreter
  m_interpreter->asyncExecute(options, QByteArray(), false);
}

QByteArray ScriptEnergy::writeCoordinatesText(const Eigen::VectorXd& x)
{
  if (x.size() == 0 || (x.size() % 3) != 0)
    return QByteArray();

  QByteArray input;
  input.reserve(static_cast<int>(x.size() / 3) * 80);
  for (Eigen::Index i = 0; i < x.size(); i += 3) {
    appendFloatText(input, x[i]);
    input.append(' ');
    appendFloatText(input, x[i + 1]);
    input.append(' ');
    appendFloatText(input, x[i + 2]);
    input.append('\n');
  }
  return input;
}

QByteArray ScriptEnergy::writeCoordinatesBinary(const Eigen::VectorXd& x,
                                                bool requestGradient) const
{
  if (x.size() == 0 || (x.size() % 3) != 0)
    return QByteArray();

  const quint16 flags = requestGradient ? FLAG_REQUEST_GRADIENT : 0;
  const quint32 atomCount = static_cast<quint32>(x.size() / 3);
  const quint32 payloadBytes = static_cast<quint32>(x.size() * sizeof(double));

  QByteArray input;
  input.reserve(BINARY_HEADER_SIZE + static_cast<int>(payloadBytes));
  input.append(BINARY_MAGIC, static_cast<int>(sizeof(BINARY_MAGIC)));

  quint16 versionLE = qToLittleEndian(BINARY_VERSION);
  quint16 flagsLE = qToLittleEndian(flags);
  quint32 atomCountLE = qToLittleEndian(atomCount);
  quint32 payloadBytesLE = qToLittleEndian(payloadBytes);

  input.append(reinterpret_cast<const char*>(&versionLE), sizeof(versionLE));
  input.append(reinterpret_cast<const char*>(&flagsLE), sizeof(flagsLE));
  input.append(reinterpret_cast<const char*>(&atomCountLE),
               sizeof(atomCountLE));
  input.append(reinterpret_cast<const char*>(&payloadBytesLE),
               sizeof(payloadBytesLE));

  if (QSysInfo::ByteOrder == QSysInfo::LittleEndian) {
    input.append(reinterpret_cast<const char*>(x.data()),
                 static_cast<int>(payloadBytes));
  } else {
    for (Eigen::Index i = 0; i < x.size(); ++i)
      appendFloat64LE(input, x[i]);
  }

  return input;
}

bool ScriptEnergy::parseResponseBinary(const QByteArray& response,
                                       bool requestGradient, double& energy,
                                       Eigen::VectorXd& grad) const
{
  if (response.size() < BINARY_HEADER_SIZE)
    return false;

  const char* raw = response.constData();
  if (std::memcmp(raw, BINARY_MAGIC, sizeof(BINARY_MAGIC)) != 0)
    return false;

  const auto* header = reinterpret_cast<const uchar*>(raw);
  const quint16 version = qFromLittleEndian<quint16>(header + 4);
  const quint16 flags = qFromLittleEndian<quint16>(header + 6);
  const quint32 atomCount = qFromLittleEndian<quint32>(header + 8);
  const quint32 payloadBytes = qFromLittleEndian<quint32>(header + 12);
  if (version != BINARY_VERSION)
    return false;

  if (response.size() < BINARY_HEADER_SIZE + static_cast<int>(payloadBytes))
    return false;

  const char* payload = raw + BINARY_HEADER_SIZE;
  const char* payloadEnd = payload + payloadBytes;

  if (m_molecule != nullptr &&
      atomCount != static_cast<quint32>(m_molecule->atomCount()))
    return false;

  if ((flags & FLAG_RESPONSE_ERROR) != 0) {
    appendError(std::string(payload, payloadEnd), false);
    return false;
  }

  if (requestGradient) {
    if (atomCount != static_cast<quint32>(grad.size() / 3))
      return false;
    if (payloadBytes != static_cast<quint32>(grad.size() * sizeof(double)))
      return false;

    if (QSysInfo::ByteOrder == QSysInfo::LittleEndian) {
      std::memcpy(grad.data(), payload, payloadBytes);
    } else {
      for (Eigen::Index i = 0; i < grad.size(); ++i) {
        double value = 0.0;
        if (!readFloat64LE(payload + i * sizeof(double), payloadEnd, value))
          return false;
        grad[i] = value;
      }
    }
    return true;
  }

  if (payloadBytes != sizeof(double))
    return false;

  if (QSysInfo::ByteOrder == QSysInfo::LittleEndian) {
    std::memcpy(&energy, payload, sizeof(double));
    return true;
  }

  return readFloat64LE(payload, payloadEnd, energy);
}

bool ScriptEnergy::readBinaryFrame(const QByteArray& input, QByteArray& frame)
{
  if (m_interpreter == nullptr)
    return false;

  constexpr int timeoutMs = 5000;
  QElapsedTimer timer;
  timer.start();

  frame = m_interpreter->asyncWriteAndResponseRaw(input, timeoutMs);
  if (frame.isEmpty()) {
    appendError("No binary response received from script.");
    return false;
  }

  while (frame.size() < BINARY_HEADER_SIZE && timer.elapsed() < timeoutMs) {
    const int remainingMs =
      std::max(1, timeoutMs - static_cast<int>(timer.elapsed()));
    const QByteArray chunk =
      m_interpreter->asyncWriteAndResponseRaw(QByteArray(), remainingMs);
    if (chunk.isEmpty())
      break;
    frame += chunk;
  }

  if (frame.size() < BINARY_HEADER_SIZE) {
    appendError("Truncated binary header from script response.");
    return false;
  }

  const auto* header = reinterpret_cast<const uchar*>(frame.constData());
  if (std::memcmp(frame.constData(), BINARY_MAGIC, sizeof(BINARY_MAGIC)) != 0) {
    appendError("Invalid binary response magic.");
    return false;
  }

  const quint16 version = qFromLittleEndian<quint16>(header + 4);
  const quint32 payloadBytes = qFromLittleEndian<quint32>(header + 12);
  if (version != BINARY_VERSION) {
    appendError("Unsupported binary response version.");
    return false;
  }

  const qint64 totalBytes =
    BINARY_HEADER_SIZE + static_cast<qint64>(payloadBytes);
  while (frame.size() < totalBytes && timer.elapsed() < timeoutMs) {
    const int remainingMs =
      std::max(1, timeoutMs - static_cast<int>(timer.elapsed()));
    const QByteArray chunk =
      m_interpreter->asyncWriteAndResponseRaw(QByteArray(), remainingMs);
    if (chunk.isEmpty())
      break;
    frame += chunk;
  }

  if (frame.size() < totalBytes) {
    appendError("Truncated binary response payload.");
    return false;
  }
  if (frame.size() > totalBytes) {
    appendError("Binary response contained trailing bytes.");
    return false;
  }

  return true;
}

bool ScriptEnergy::evaluateBinary(const Eigen::VectorXd& x,
                                  bool requestGradient, double& energy,
                                  Eigen::VectorXd& grad)
{
  const QByteArray input = writeCoordinatesBinary(x, requestGradient);
  if (input.isEmpty()) {
    appendError("Invalid coordinates for binary request.");
    return false;
  }

  QByteArray response;
  if (!readBinaryFrame(input, response))
    return false;

  return parseResponseBinary(response, requestGradient, energy, grad);
}

Real ScriptEnergy::value(const Eigen::VectorXd& x)
{
  if (m_molecule == nullptr || m_interpreter == nullptr)
    return 0.0; // nothing to do

  double energy = 0.0;
  if (m_protocol == Protocol::BinaryV1) {
    Eigen::VectorXd unusedGrad;
    if (!evaluateBinary(x, false, energy, unusedGrad)) {
      return std::numeric_limits<Real>::quiet_NaN();
    }
    energy += constraintEnergies(x);
    return energy;
  }

  QByteArray input = writeCoordinatesText(x);
  if (input.isEmpty()) {
    appendError("Invalid coordinates for text request.");
    return std::numeric_limits<Real>::quiet_NaN();
  }

  QByteArray result = m_interpreter->asyncWriteAndResponse(input);

  // Find "AvogadroEnergy:" and parse the value directly from raw bytes
  const char* data = result.constData();
  const char* end = data + result.size();
  constexpr char marker[] = "AvogadroEnergy:";
  constexpr size_t markerLen = sizeof(marker) - 1;

  const char* pos = std::search(data, end, marker, marker + markerLen);
  if (pos != end) {
    pos += markerLen;
    while (pos < end && (*pos == ' ' || *pos == '\t'))
      ++pos;
    double parsedEnergy = 0.0;
    if (readFloatText(pos, end, parsedEnergy))
      energy = parsedEnergy;
  }

  energy += constraintEnergies(x);
  return energy;
}

void ScriptEnergy::gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (!m_gradients) {
    EnergyCalculator::gradient(x, grad);
    return;
  }

  if (m_protocol == Protocol::BinaryV1) {
    double unusedEnergy = 0.0;
    if (!evaluateBinary(x, true, unusedEnergy, grad)) {
      grad.setConstant(std::numeric_limits<Real>::quiet_NaN());
      return;
    }
    cleanGradients(grad);
    constraintGradients(x, grad);
    return;
  }

  QByteArray input = writeCoordinatesText(x);
  if (input.isEmpty()) {
    appendError("Invalid coordinates for text request.");
    grad.setConstant(std::numeric_limits<Real>::quiet_NaN());
    return;
  }

  QByteArray result = m_interpreter->asyncWriteAndResponse(input);

  // Parse directly from raw bytes — no QString/QStringList overhead
  const char* data = result.constData();
  const char* end = data + result.size();
  constexpr char marker[] = "AvogadroGradient:";
  constexpr size_t markerLen = sizeof(marker) - 1;

  const char* pos = std::search(data, end, marker, marker + markerLen);
  if (pos != end) {
    // Skip to the next line
    pos = static_cast<const char*>(std::memchr(pos, '\n', end - pos));
    if (pos)
      ++pos;

    Eigen::Index i = 0;
    while (pos && pos < end && i + 2 < x.size()) {
      // Skip whitespace
      while (pos < end && (*pos == ' ' || *pos == '\t' || *pos == '\r'))
        ++pos;
      if (pos >= end || *pos == '\n') {
        if (pos < end)
          ++pos;
        continue;
      }

      double gx, gy, gz;
      if (!readFloatText(pos, end, gx))
        break;

      while (pos < end && (*pos == ' ' || *pos == '\t'))
        ++pos;
      if (!readFloatText(pos, end, gy))
        break;

      while (pos < end && (*pos == ' ' || *pos == '\t'))
        ++pos;
      if (!readFloatText(pos, end, gz))
        break;

      grad[i] = gx;
      grad[i + 1] = gy;
      grad[i + 2] = gz;
      i += 3;

      // Skip to next line
      while (pos < end && *pos != '\n')
        ++pos;
      if (pos < end)
        ++pos;
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

ScriptEnergy::Protocol ScriptEnergy::stringToProtocol(const std::string& str)
{
  // Check for "binary" mode
  // this will change if the binary format changes
  if (str.rfind("binary", 0) == 0)
    return Protocol::BinaryV1;

  return Protocol::TextV1;
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
  m_protocol = Protocol::TextV1;
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

  // optional protocol, defaults to text-v1
  if (metaData["protocol"].isString()) {
    const std::string protocolString =
      metaData["protocol"].toString().toStdString();
    if (protocolString == "text-v1" || protocolString == "binary-v1") {
      m_protocol = stringToProtocol(protocolString);
    } else {
      qWarning() << "Error parsing metadata for energy script:"
                 << scriptFilePath() << "\n"
                 << "Member 'protocol' not recognized:"
                 << protocolString.c_str()
                 << "\nValid values are text-v1 or binary-v1.\n"
                 << output;
      return;
    }
  }

  // check ions, radicals, unit cells
  /* e.g.,
        "protocol": "binary-v1",
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
      continue;
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
