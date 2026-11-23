/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "scriptenergy.h"

#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>
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
constexpr quint16 FLAG_BATCH_MODE = 0x0002;
constexpr quint16 FLAG_REQUEST_ENERGY_AND_GRADIENT = 0x0004;
constexpr quint16 FLAG_REQUEST_HESSIAN = 0x0008;
// Sent once by the server (zero payload, atom_count = its num_atoms) when it
// has finished loading and is ready for requests. Only sent when the
// environment variable below is set; older servers never send it.
constexpr quint16 FLAG_READY = 0x0010;

constexpr char READY_ENVIRONMENT_VARIABLE[] = "AVOGADRO_ENERGY_READY";

// The first exchange after the process starts has to cover importing a deep
// learning framework and loading its model, which takes 7-16 s for the plugins
// we know of. Model weights are fetched when the plugin is set up, not here.
// The budget covers everything from launch to the first successful reply,
// including a JIT compile on the first evaluation, and is not per wait.
constexpr int STARTUP_TIMEOUT_MS = 60000;

// Consecutive launches that never produced a successful reply before we stop
// restarting the plugin on every request.
constexpr int MAX_FAILED_STARTS = 2;

// QByteArray cannot hold more than this, and no sane frame comes close.
constexpr qint64 MAX_FRAME_BYTES = 0x7fffffff - BINARY_HEADER_SIZE;

enum class FrameState
{
  NeedMore, // a valid prefix of a frame; wait for more bytes
  Complete, // buffer holds at least one whole frame
  Invalid   // bad magic or version, or an absurd size
};

// Examine the start of @p buffer without consuming it. On Complete, @p total
// is the byte length of the first frame and @p flags/@p atomCount/@p payload
// describe it; on Invalid, @p why says what is wrong.
FrameState inspectFrame(const QByteArray& buffer, qint64& total, quint16& flags,
                        quint32& atomCount, quint32& payloadBytes,
                        const char*& why)
{
  // Judge the magic as soon as any of it has arrived so that garbage fails
  // fast rather than waiting out a timeout for a header that will never come.
  const auto prefix =
    static_cast<int>(std::min<qsizetype>(buffer.size(), sizeof(BINARY_MAGIC)));
  if (std::memcmp(buffer.constData(), BINARY_MAGIC, prefix) != 0) {
    why = "Invalid binary response magic.";
    return FrameState::Invalid;
  }
  if (buffer.size() < BINARY_HEADER_SIZE)
    return FrameState::NeedMore;

  const auto* header = reinterpret_cast<const uchar*>(buffer.constData());
  const quint16 version = qFromLittleEndian<quint16>(header + 4);
  flags = qFromLittleEndian<quint16>(header + 6);
  atomCount = qFromLittleEndian<quint32>(header + 8);
  payloadBytes = qFromLittleEndian<quint32>(header + 12);
  if (version != BINARY_VERSION) {
    why = "Unsupported binary response version.";
    return FrameState::Invalid;
  }
  if (static_cast<qint64>(payloadBytes) > MAX_FRAME_BYTES) {
    why = "Binary response is too large.";
    return FrameState::Invalid;
  }

  total = BINARY_HEADER_SIZE + static_cast<qint64>(payloadBytes);
  return buffer.size() >= total ? FrameState::Complete : FrameState::NeedMore;
}

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

  // Not strtod: Qt sets the C locale from the environment, and strtod would
  // then read "-76.4123" as -76 wherever the decimal separator is a comma.
  const char* parsedEnd = Core::parseDouble(pos, end, value);
  if (parsedEnd == nullptr)
    return false;

  pos = parsedEnd;
  return true;
}

} // namespace

ScriptEnergy::ScriptEnergy(const QString& scriptFileName_)
  : m_interpreter(new QtGui::PythonScript(scriptFileName_)),
    m_inputFormat(NotUsed), m_protocol(Protocol::TextV1), m_molecule(nullptr),
    m_valid(true), m_gradients(false), m_hessians(false), m_batch(false),
    m_ions(false), m_radicals(false), m_unitCells(false)
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
  m_hessians = support.value("hessians", false).toBool();
  m_batch = support.value("batch", false).toBool();
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
      m_userOptionsSchema = QtGui::PackageManager::resolveUserOptions(
        userOptionsRel, m_interpreter->packageDir(),
        m_interpreter->packageCommand(), m_interpreter->packageIdentifier());
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
  m_hessians = other.m_hessians;
  m_batch = other.m_batch;
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
  m_needsRestart = false;
  m_processStarted = false;
  m_failedStarts = 0;

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

  startProcess();
}

bool ScriptEnergy::startProcess()
{
  if (m_interpreter == nullptr || m_molecule == nullptr)
    return false;

  // Always begin from a clean slate: a fresh QProcess has fresh pipes, so no
  // byte written by an earlier process can ever be read from the new one.
  m_interpreter->asyncTerminate();
  m_needsRestart = false;
  m_processStarted = false;

  QByteArray bootstrapInput;
  if (!buildBootstrapInput(bootstrapInput))
    return false;

  // construct the command line options
  QStringList options;
  m_interpreter->clearEnvironmentVariables();
  if (m_protocol == Protocol::BinaryV1) {
    options << "--protocol"
            << "binary-v1";
    // Ask the server to announce when it has loaded its model. Older servers
    // ignore the variable, and the variable keeps newer servers from sending
    // a frame an older Avogadro would not understand.
    m_interpreter->setEnvironmentVariable(
      QString::fromLatin1(READY_ENVIRONMENT_VARIABLE), QStringLiteral("1"));
  }

  // Start the long-running interpreter and keep stdin open for coordinate
  // requests after bootstrapping the model from JSON.
  m_awaitingStartup = true;
  m_readySeen = false;
  m_launchTimer.start();
  if (!m_interpreter->asyncExecute(options, bootstrapInput, false, false)) {
    m_interpreter->asyncTerminate();
    return false;
  }
  m_processStarted = true;
  return true;
}

void ScriptEnergy::discardProcess()
{
  if (m_interpreter == nullptr)
    return;

  // Kill the process outright. Whatever it still has in flight (a late reply
  // to a request we gave up on, say) dies with it, and the next request
  // starts a new process whose pipes cannot contain it.
  m_interpreter->asyncTerminate();
  // A launch that dies before answering anything counts toward the restart
  // cap; a long-running plugin that later fails does not.
  if (m_processStarted && m_awaitingStartup)
    ++m_failedStarts;
  if (m_processStarted)
    m_needsRestart = true;
  m_processStarted = false;
  m_awaitingStartup = true;
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
                                                quint16 requestFlags) const
{
  if (x.size() == 0 || (x.size() % 3) != 0)
    return QByteArray();

  const quint16 flags = requestFlags;
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
                                       quint16 requestFlags, double* energy,
                                       Eigen::VectorXd* grad,
                                       Eigen::MatrixXd* hess) const
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

  if ((flags & FLAG_RESPONSE_ERROR) != 0) {
    appendError(std::string(payload, payloadEnd), false);
    return false;
  }

  if (m_molecule != nullptr &&
      atomCount != static_cast<quint32>(m_molecule->atomCount()))
    return false;

  const auto readDoubles = [](const char* src, const char* srcEnd, double* dest,
                              Eigen::Index count) -> bool {
    const auto byteCount = count * static_cast<Eigen::Index>(sizeof(double));
    if (srcEnd - src < byteCount)
      return false;
    if (QSysInfo::ByteOrder == QSysInfo::LittleEndian) {
      std::memcpy(dest, src, byteCount);
    } else {
      for (Eigen::Index i = 0; i < count; ++i) {
        if (!readFloat64LE(src + i * sizeof(double), srcEnd, dest[i]))
          return false;
      }
    }
    return true;
  };

  // Hessian response: (3N)^2 doubles, row-major on wire
  if ((requestFlags & FLAG_REQUEST_HESSIAN) != 0 && hess != nullptr) {
    const Eigen::Index dim = static_cast<Eigen::Index>(atomCount) * 3;
    const quint32 expectedBytes =
      static_cast<quint32>(dim * dim * sizeof(double));
    if (payloadBytes != expectedBytes)
      return false;
    if (QSysInfo::ByteOrder == QSysInfo::LittleEndian) {
      // Map row-major wire data directly into column-major Eigen matrix
      Eigen::Map<const Eigen::Matrix<double, Eigen::Dynamic, Eigen::Dynamic,
                                     Eigen::RowMajor>>
        rowMajorMap(reinterpret_cast<const double*>(payload), dim, dim);
      *hess = rowMajorMap;
    } else {
      // Read with byte-swap into a temporary, then transpose
      hess->resize(dim, dim);
      Eigen::MatrixXd rowMajor(dim, dim);
      if (!readDoubles(payload, payloadEnd, rowMajor.data(), dim * dim))
        return false;
      *hess = rowMajor.transpose();
    }
    return true;
  }

  // Fused energy + gradient response: 1 double energy + 3N doubles gradient
  if ((requestFlags & FLAG_REQUEST_ENERGY_AND_GRADIENT) != 0) {
    if (grad == nullptr || energy == nullptr)
      return false;
    const quint32 gradBytes =
      static_cast<quint32>(grad->size() * sizeof(double));
    if (payloadBytes != sizeof(double) + gradBytes)
      return false;
    if (!readDoubles(payload, payloadEnd, energy, 1))
      return false;
    if (!readDoubles(payload + sizeof(double), payloadEnd, grad->data(),
                     grad->size()))
      return false;
    return true;
  }

  // Gradient-only response
  if ((requestFlags & FLAG_REQUEST_GRADIENT) != 0) {
    if (grad == nullptr)
      return false;
    if (atomCount != static_cast<quint32>(grad->size() / 3))
      return false;
    if (payloadBytes != static_cast<quint32>(grad->size() * sizeof(double)))
      return false;
    return readDoubles(payload, payloadEnd, grad->data(), grad->size());
  }

  // Energy-only response
  if (energy == nullptr)
    return false;
  if (payloadBytes != sizeof(double))
    return false;
  return readDoubles(payload, payloadEnd, energy, 1);
}

bool ScriptEnergy::readBinaryFrame(const QByteArray& input, QByteArray& frame,
                                   int timeoutMs)
{
  frame.clear();
  if (m_interpreter == nullptr)
    return false;

  // A previous exchange failed and the process was killed: start a new one
  // (re-bootstrapping the model) before sending anything.
  if (m_needsRestart && m_failedStarts >= MAX_FAILED_STARTS) {
    // Do not pay for another model load on every optimizer step.
    appendError("Energy plugin " + (m_name.empty() ? m_identifier : m_name) +
                " failed to start twice; see its error output. Select the "
                "model again to retry.");
    return false;
  }
  if (m_needsRestart && !startProcess()) {
    appendError("Could not restart the script after an earlier failure.");
    return false;
  }
  if (!m_processStarted) {
    appendError("The script is not running.");
    return false;
  }

  if (!m_interpreter->asyncWriteRaw(input)) {
    appendError("Could not send the request to the script.");
    discardProcess();
    return false;
  }

  // Until the first successful reply, everything is measured against one
  // budget from launch (READY does not shorten it: the first evaluation may
  // still compile). Never allow less than the normal timeout.
  const int budgetMs =
    m_awaitingStartup
      ? static_cast<int>(std::max<qint64>(
          STARTUP_TIMEOUT_MS - m_launchTimer.elapsed(), timeoutMs))
      : timeoutMs;
  QElapsedTimer timer;
  timer.start();

  QByteArray buffer;
  for (;;) {
    qint64 total = 0;
    quint16 flags = 0;
    quint32 atomCount = 0;
    quint32 payloadBytes = 0;
    const char* why = nullptr;

    // Frames are peeled off the front of the buffer one at a time, so bytes
    // that arrive together with a READY frame are never lost.
    const FrameState state =
      inspectFrame(buffer, total, flags, atomCount, payloadBytes, why);

    if (state == FrameState::Invalid) {
      appendError(why);
      discardProcess();
      return false;
    }

    if (state == FrameState::Complete) {
      if ((flags & FLAG_READY) != 0) {
        // Only a server that has just started may announce itself, once, and
        // it must describe the molecule we gave it.
        const bool expected = m_awaitingStartup && !m_readySeen;
        const bool sizeOk =
          m_molecule == nullptr ||
          atomCount == static_cast<quint32>(m_molecule->atomCount());
        if (!expected || payloadBytes != 0 || !sizeOk) {
          appendError(expected
                        ? "Script's ready message does not match the molecule."
                        : "Unexpected ready message from script.");
          discardProcess();
          return false;
        }
        m_readySeen = true;
        buffer.remove(0, static_cast<qsizetype>(total));
        continue;
      }

      if (buffer.size() != total) {
        // One request, one reply: anything more means we are out of step.
        appendError("Binary response contained trailing bytes.");
        discardProcess();
        return false;
      }

      frame = buffer;
      return true;
    }

    const qint64 remainingMs = budgetMs - timer.elapsed();
    const QByteArray chunk =
      remainingMs > 0
        ? m_interpreter->asyncReadRaw(static_cast<int>(remainingMs))
        : QByteArray();
    if (chunk.isEmpty()) {
      if (buffer.isEmpty())
        appendError(
          m_awaitingStartup
            ? "Timed out waiting for the script to start, or it exited."
            : "No binary response received from script.");
      else
        appendError("Truncated binary response from script.");
      discardProcess();
      return false;
    }
    buffer += chunk;
  }
}

bool ScriptEnergy::evaluateBinary(const Eigen::VectorXd& x,
                                  quint16 requestFlags, double* energy,
                                  Eigen::VectorXd* grad, Eigen::MatrixXd* hess)
{
  const QByteArray input = writeCoordinatesBinary(x, requestFlags);
  if (input.isEmpty()) {
    appendError("Invalid coordinates for binary request.");
    return false;
  }

  QByteArray response;
  if (!readBinaryFrame(input, response))
    return false;

  if (parseResponseBinary(response, requestFlags, energy, grad, hess)) {
    noteResponseOk();
    return true;
  }
  rejectResponse(response);
  return false;
}

QByteArray ScriptEnergy::writeBatchCoordinatesBinary(
  const std::vector<Eigen::VectorXd>& coords, quint16 requestFlags) const
{
  if (coords.empty())
    return QByteArray();

  // All frames must share the same atom count and be non-empty multiples of 3.
  const Eigen::Index size = coords.front().size();
  if (size == 0 || (size % 3) != 0)
    return QByteArray();
  for (const auto& x : coords) {
    if (x.size() != size)
      return QByteArray();
  }

  const quint16 flags = requestFlags | FLAG_BATCH_MODE;
  const quint32 atomCount = static_cast<quint32>(size / 3);
  const quint32 batchSize = static_cast<quint32>(coords.size());
  // payload = uint32 batchSize + batchSize * 3N doubles
  const quint32 coordBytes = static_cast<quint32>(batchSize) *
                             static_cast<quint32>(size) *
                             static_cast<quint32>(sizeof(double));
  const quint32 payloadBytes =
    static_cast<quint32>(sizeof(quint32)) + coordBytes;

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

  quint32 batchSizeLE = qToLittleEndian(batchSize);
  input.append(reinterpret_cast<const char*>(&batchSizeLE),
               sizeof(batchSizeLE));

  for (const auto& x : coords) {
    if (QSysInfo::ByteOrder == QSysInfo::LittleEndian) {
      input.append(reinterpret_cast<const char*>(x.data()),
                   static_cast<int>(x.size() * sizeof(double)));
    } else {
      for (Eigen::Index i = 0; i < x.size(); ++i)
        appendFloat64LE(input, x[i]);
    }
  }

  return input;
}

bool ScriptEnergy::parseBatchResponseBinary(
  const QByteArray& response, quint16 requestFlags, std::size_t expectedBatch,
  std::vector<double>* energies, std::vector<Eigen::VectorXd>* grads) const
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

  if ((flags & FLAG_RESPONSE_ERROR) != 0) {
    appendError(std::string(payload, payloadEnd), false);
    return false;
  }

  if ((flags & FLAG_BATCH_MODE) == 0)
    return false;

  if (m_molecule != nullptr &&
      atomCount != static_cast<quint32>(m_molecule->atomCount()))
    return false;

  // payload starts with uint32 batchSize
  if (payloadBytes < sizeof(quint32))
    return false;
  const quint32 batchSize =
    qFromLittleEndian<quint32>(reinterpret_cast<const uchar*>(payload));
  if (batchSize != static_cast<quint32>(expectedBatch))
    return false;

  const char* data = payload + sizeof(quint32);
  const Eigen::Index dataDoubles =
    static_cast<Eigen::Index>(payloadEnd - data) /
    static_cast<Eigen::Index>(sizeof(double));

  const auto readDoubles = [](const char* src, const char* srcEnd, double* dest,
                              Eigen::Index count) -> bool {
    const auto byteCount = count * static_cast<Eigen::Index>(sizeof(double));
    if (srcEnd - src < byteCount)
      return false;
    if (QSysInfo::ByteOrder == QSysInfo::LittleEndian) {
      std::memcpy(dest, src, byteCount);
    } else {
      for (Eigen::Index i = 0; i < count; ++i) {
        if (!readFloat64LE(src + i * sizeof(double), srcEnd, dest[i]))
          return false;
      }
    }
    return true;
  };

  if ((requestFlags & FLAG_REQUEST_GRADIENT) != 0) {
    if (grads == nullptr)
      return false;
    const Eigen::Index frameSize = static_cast<Eigen::Index>(atomCount) * 3;
    if (dataDoubles != frameSize * static_cast<Eigen::Index>(batchSize))
      return false;
    grads->assign(batchSize, Eigen::VectorXd::Zero(frameSize));
    const char* cursor = data;
    for (quint32 b = 0; b < batchSize; ++b) {
      if (!readDoubles(cursor, payloadEnd, (*grads)[b].data(), frameSize))
        return false;
      cursor += frameSize * sizeof(double);
    }
    return true;
  }

  // energy-only batch response
  if (energies == nullptr)
    return false;
  if (dataDoubles != static_cast<Eigen::Index>(batchSize))
    return false;
  energies->assign(batchSize, 0.0);
  return readDoubles(data, payloadEnd, energies->data(),
                     static_cast<Eigen::Index>(batchSize));
}

bool ScriptEnergy::evaluateBatchBinary(
  const std::vector<Eigen::VectorXd>& coords, quint16 requestFlags,
  std::vector<double>* energies, std::vector<Eigen::VectorXd>* grads)
{
  const QByteArray input = writeBatchCoordinatesBinary(coords, requestFlags);
  if (input.isEmpty()) {
    appendError("Invalid coordinates for binary batch request.");
    return false;
  }

  // Scale the timeout with batch size: a base budget plus per-frame allowance
  // so a large ML batch doesn't trip the default single-frame timeout.
  const int timeoutMs = 5000 + static_cast<int>(coords.size()) * 250;

  QByteArray response;
  if (!readBinaryFrame(input, response, timeoutMs))
    return false;

  if (parseBatchResponseBinary(response, requestFlags, coords.size(), energies,
                               grads)) {
    noteResponseOk();
    return true;
  }
  rejectResponse(response);
  return false;
}

void ScriptEnergy::noteResponseOk()
{
  // The plugin has loaded and answered: startup is over and it is trusted
  // again, whatever happened to earlier launches.
  m_awaitingStartup = false;
  m_failedStarts = 0;
}

void ScriptEnergy::rejectResponse(const QByteArray& response)
{
  // A well-formed error frame is the script saying "I could not do that"; the
  // stream is still in step, so the process is kept. Anything else that did
  // not parse (wrong size, wrong atom count) means we no longer know what the
  // script is answering, so start over rather than risk misreading later ones.
  const bool isError =
    response.size() >= BINARY_HEADER_SIZE &&
    (qFromLittleEndian<quint16>(
       reinterpret_cast<const uchar*>(response.constData()) + 6) &
     FLAG_RESPONSE_ERROR) != 0;
  if (!isError) {
    appendError("Malformed response from script.");
    discardProcess();
  }
}

std::vector<Real> ScriptEnergy::valueBatch(
  const std::vector<Eigen::VectorXd>& coords)
{
  if (!supportsBatch() || m_molecule == nullptr || m_interpreter == nullptr)
    return EnergyCalculator::valueBatch(coords);

  std::vector<double> energies;
  if (!evaluateBatchBinary(coords, 0, &energies, nullptr)) {
    // fall back to the per-frame loop on any protocol failure
    return EnergyCalculator::valueBatch(coords);
  }

  // add constraint energies per frame
  for (std::size_t i = 0; i < energies.size() && i < coords.size(); ++i)
    energies[i] += constraintEnergies(coords[i]);

  return energies;
}

void ScriptEnergy::gradientBatch(const std::vector<Eigen::VectorXd>& coords,
                                 std::vector<Eigen::VectorXd>& grads)
{
  if (!supportsBatch() || !m_gradients || m_molecule == nullptr ||
      m_interpreter == nullptr) {
    EnergyCalculator::gradientBatch(coords, grads);
    return;
  }

  if (!evaluateBatchBinary(coords, FLAG_REQUEST_GRADIENT, nullptr, &grads)) {
    EnergyCalculator::gradientBatch(coords, grads);
    return;
  }

  // clean and apply constraints per frame, matching the single-shot path
  for (std::size_t i = 0; i < grads.size() && i < coords.size(); ++i) {
    cleanGradients(grads[i]);
    constraintGradients(coords[i], grads[i]);
  }
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
    if (!evaluateBinary(x, 0, &energy)) {
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
    if (!readFloatText(pos, end, parsedEnergy)) {
      appendError("Could not parse the energy after \"AvogadroEnergy:\".");
      return std::numeric_limits<Real>::quiet_NaN();
    }
    energy = parsedEnergy;
  }

  energy += constraintEnergies(x);
  return energy;
}

Real ScriptEnergy::evaluate(const Eigen::VectorXd& x, Eigen::VectorXd* grad)
{
  if (grad == nullptr)
    return value(x);

  // Optimizers may pass an uninitialized/incorrectly-sized gradient buffer.
  if (grad->rows() != x.rows())
    grad->resize(x.rows());
  grad->setZero();

  if (!m_gradients)
    return EnergyCalculator::evaluate(x, grad);

  if (m_protocol == Protocol::BinaryV1) {
    double energy = 0.0;
    if (!evaluateBinary(x, FLAG_REQUEST_ENERGY_AND_GRADIENT, &energy, grad)) {
      grad->setConstant(std::numeric_limits<Real>::quiet_NaN());
      return std::numeric_limits<Real>::quiet_NaN();
    }
    cleanGradients(*grad);
    constraintGradients(x, *grad);
    energy += constraintEnergies(x);
    return energy;
  }

  // Text protocol parsers are currently separate for value and gradient.
  gradient(x, *grad);
  return value(x);
}

void ScriptEnergy::gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (grad.rows() != x.rows())
    grad.resize(x.rows());
  grad.setZero();

  if (!m_gradients) {
    EnergyCalculator::gradient(x, grad);
    return;
  }

  if (m_protocol == Protocol::BinaryV1) {
    if (!evaluateBinary(x, FLAG_REQUEST_GRADIENT, nullptr, &grad)) {
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

void ScriptEnergy::hessian(const Eigen::VectorXd& x, Eigen::MatrixXd& hess)
{
  if (!m_hessians || m_protocol != Protocol::BinaryV1) {
    // Fall back to numerical Hessian
    // Text-mode would be really slow anyway
    EnergyCalculator::hessian(x, hess);
    return;
  }

  if (!evaluateBinary(x, FLAG_REQUEST_HESSIAN, nullptr, nullptr, &hess)) {
    // something went wrong
    const Eigen::Index dim = x.size();
    hess = Eigen::MatrixXd::Constant(dim, dim,
                                     std::numeric_limits<Real>::quiet_NaN());
  }
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
  m_hessians = false;
  m_batch = false;
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
