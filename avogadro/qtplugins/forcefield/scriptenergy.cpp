/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "scriptenergy.h"

#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/packagemanager.h>
#include <avogadro/qtgui/pythonscript.h>

// formats supported in scripts
#include <avogadro/io/cjsonformat.h>
#include <avogadro/io/cmlformat.h>
#include <avogadro/io/mdlformat.h>
#include <avogadro/io/pdbformat.h>
#include <avogadro/io/sdfformat.h>
#include <avogadro/io/xyzformat.h>

#include <QtCore/QDebug>
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

  // Optional package-provided user-options schema.
  m_userOptionsSchema = QJsonObject();
  const QVariant userOptionsVar = metadata.value("user-options");
  if (userOptionsVar.typeId() == QMetaType::QVariantMap) {
    m_userOptionsSchema = QJsonObject::fromVariantMap(userOptionsVar.toMap());
  } else {
    const QString userOptionsRel = userOptionsVar.toString();
    if (!userOptionsRel.isEmpty()) {
      QString userOptionsPath = userOptionsRel;
      if (!m_interpreter->packageDir().isEmpty()) {
        userOptionsPath = m_interpreter->packageDir() + '/' + userOptionsRel;
      }
      m_userOptionsSchema =
        QtGui::PackageManager::loadOptionsFromFile(userOptionsPath);
    }
  }

  m_valid =
    !m_identifier.empty() && !m_name.empty() && m_inputFormat != NotUsed;
}

QString ScriptEnergy::scriptFilePath() const
{
  return m_interpreter->scriptFilePath();
}

std::string ScriptEnergy::userOptions() const
{
  if (m_userOptionsSchema.isEmpty())
    return std::string();

  return QJsonDocument(m_userOptionsSchema)
    .toJson(QJsonDocument::Compact)
    .toStdString();
}

bool ScriptEnergy::setUserOptions(const std::string& optionsJson)
{
  if (optionsJson.empty()) {
    m_userOptionsValues = QJsonObject();
    return true;
  }

  QJsonParseError parseError;
  const QJsonDocument doc = QJsonDocument::fromJson(
    QByteArray::fromStdString(optionsJson), &parseError);
  if (parseError.error != QJsonParseError::NoError || !doc.isObject())
    return false;

  m_userOptionsValues = doc.object();
  return true;
}

Calc::EnergyCalculator* ScriptEnergy::newInstance() const
{
  auto* copy = new ScriptEnergy();
  copy->m_interpreter->setPackageInfo(m_interpreter->packageDir(),
                                      m_interpreter->packageCommand(),
                                      m_interpreter->packageIdentifier());
  copy->copyMetaDataFrom(*this);
  return copy;
}

void ScriptEnergy::copyMetaDataFrom(const ScriptEnergy& other)
{
  m_identifier = other.m_identifier;
  m_name = other.m_name;
  m_description = other.m_description;
  m_inputFormat = other.m_inputFormat;
  m_formatString = other.m_formatString;
  m_userOptionsSchema = other.m_userOptionsSchema;
  m_userOptionsValues = other.m_userOptionsValues;
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
  if (!m_interpreter->isPackageMode()) {
    appendError("Energy scripts must run in package mode.");
    return;
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

  QByteArray bootstrapInput;
  if (!buildBootstrapInput(bootstrapInput))
    return;

  // construct the command line options
  QStringList options;
  if (m_protocol == Protocol::BinaryV1)
    options << "--protocol"
            << "binary-v1";

  // Start the long-running interpreter and keep stdin open for coordinate
  // requests after bootstrapping the model from JSON.
  m_interpreter->asyncExecute(options, bootstrapInput, false, false);
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

bool ScriptEnergy::buildBootstrapInput(QByteArray& input) const
{
  if (m_molecule == nullptr) {
    return false;
  }

  QScopedPointer<Io::FileFormat> format(createFileFormat(m_inputFormat));
  if (format.isNull()) {
    appendError("Invalid input format.");
    return false;
  }

  std::string moleculeString;
  if (!format->writeString(moleculeString, *m_molecule)) {
    appendError(format->error(), false);
    return false;
  }

  QJsonObject request;
  request.insert(QStringLiteral("charge"), m_molecule->totalCharge());
  request.insert(QStringLiteral("spin"), m_molecule->totalSpinMultiplicity());

  QJsonArray selectedList;
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (m_molecule->atomSelected(i))
      selectedList.append(static_cast<qint64>(i));
  }
  request.insert(QStringLiteral("selectedAtoms"), selectedList);

  if (m_formatString == QLatin1String("cjson")) {
    QJsonParseError parseError;
    const QJsonDocument parsed = QJsonDocument::fromJson(
      QByteArray::fromStdString(moleculeString), &parseError);
    if (parseError.error != QJsonParseError::NoError || !parsed.isObject()) {
      appendError("Failed to serialize cjson bootstrap input.");
      return false;
    }
    request.insert(QStringLiteral("cjson"), parsed.object());
  } else {
    request.insert(m_formatString, QString::fromStdString(moleculeString));
  }

  // Package energy scripts receive user-selected values under "options".
  request.insert(QStringLiteral("options"), m_userOptionsValues);

  input = QJsonDocument(request).toJson(QJsonDocument::Compact);
  input.append('\n');
  return true;
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
  m_userOptionsSchema = QJsonObject();
  m_userOptionsValues = QJsonObject();
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

} // namespace Avogadro::QtPlugins
