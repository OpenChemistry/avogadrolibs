/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "obprocess.h"

#include <avogadro/qtgui/utilities.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QProcess>
#include <QtCore/QTemporaryFile>

#include <QRegularExpression>

namespace Avogadro::QtPlugins {

OBProcess::OBProcess(QObject* parent_)
  : QObject(parent_), m_processLocked(false), m_aborted(false),
    m_process(new QProcess(this)), m_conformerOutputFile(nullptr),
#if defined(_WIN32)
    m_obabelExecutable("obabel.exe")
#else
    m_obabelExecutable("obabel")
#endif
{
  // Read the AVO_OBABEL_EXECUTABLE env var to optionally override the
  // executable used for obabel.
  QByteArray obabelExec = qgetenv("AVO_OBABEL_EXECUTABLE");
  if (!obabelExec.isEmpty()) {
    m_obabelExecutable = obabelExec;
  } else {
    // If not overridden, look for an obabel next to the executable.
    QDir baseDir(QCoreApplication::applicationDirPath());
    if (!baseDir.absolutePath().startsWith("/usr/") &&
        QFileInfo(baseDir.absolutePath() + '/' + m_obabelExecutable).exists()) {
      m_obabelExecutable = baseDir.absolutePath() + '/' + m_obabelExecutable;
      QProcessEnvironment env = QProcessEnvironment::systemEnvironment();

      // Leave any setting from the environment alone.
      if (env.value("BABEL_DATADIR").isEmpty()) {
        const QString dataDir = QtGui::Utilities::openBabelDataDirectory();
        if (!dataDir.isEmpty())
          env.insert("BABEL_DATADIR", dataDir);
        else
          qDebug() << "Error, Open Babel data directory not found.";
      }

      if (env.value("BABEL_LIBDIR").isEmpty()) {
        const QString pluginDir = QtGui::Utilities::openBabelLibraryDirectory();
        if (!pluginDir.isEmpty())
          env.insert("BABEL_LIBDIR", pluginDir);
      }

      m_process->setProcessEnvironment(env);
    }
  }
}

QString OBProcess::version()
{
  QString result;

  if (!tryLockProcess()) {
    qWarning() << "OBProcess::version: process already in use.";
    return result;
  }

  executeObabel(QStringList() << "-V");

  if (m_process->waitForFinished(500))
    result = m_process->readAllStandardOutput().trimmed();

  releaseProcess();
  return result;
}

void OBProcess::abort()
{
  m_aborted = true;
  emit aborted();
}

void OBProcess::obError()
{
  qDebug() << "Process encountered an error, and did not execute correctly.";
  if (m_process) {
    qDebug() << "\tExit code:" << m_process->exitCode();
    qDebug() << "\tExit status:" << m_process->exitStatus();
    qDebug() << "\tExit output:" << m_process->readAll();
  }
}

bool OBProcess::queryReadFormats()
{
  if (!tryLockProcess()) {
    qWarning() << "OBProcess::queryReadFormats: process already in use.";
    return false;
  }

  // Setup options
  QStringList options;
  options << "-L"
          << "formats"
          << "read";

  executeObabel(options, this, SLOT(queryReadFormatsPrepare()));
  return true;
}

bool OBProcess::queryWriteFormats()
{
  if (!tryLockProcess()) {
    qWarning() << "OBProcess::queryWriteFormats: process already in use.";
    return false;
  }

  // Setup options
  QStringList options;
  options << "-L"
          << "formats"
          << "write";

  executeObabel(options, this, SLOT(queryWriteFormatsPrepare()));
  return true;
}

void OBProcess::queryReadFormatsPrepare()
{
  if (m_aborted) {
    releaseProcess();
    return;
  }

  QMultiMap<QString, QString> result;

  QString output = QString::fromLatin1(m_process->readAllStandardOutput());

  QRegularExpression parser(R"(\s*([^\s]+)\s+--\s+([^\n]+)\n)");
  QRegularExpressionMatch match;
  int pos = 0;
  while ((match = parser.match(output, pos)).hasMatch()) {
    QString extension = match.captured(1);
    QString description = match.captured(2);
    result.insertMulti(description, extension);
    pos = match.capturedEnd(0);
  }

  releaseProcess();
  emit queryReadFormatsFinished(result);
  return;
}

void OBProcess::queryWriteFormatsPrepare()
{
  if (m_aborted) {
    releaseProcess();
    return;
  }

  QMultiMap<QString, QString> result;

  QString output = QString::fromLatin1(m_process->readAllStandardOutput());

  QRegularExpression parser(R"(\s*([^\s]+)\s+--\s+([^\n]+)\n)");
  QRegularExpressionMatch match;
  int pos = 0;
  while ((match = parser.match(output, pos)).hasMatch()) {
    QString extension = match.captured(1);
    QString description = match.captured(2);

    // skip some formats that we want to ignore
    if (extension == "png" || extension == "svg" || extension == "paint" ||
        extension == "nul") {
      pos = match.capturedEnd(0);
      continue;
    }

    result.insertMulti(description, extension);
    pos = match.capturedEnd(0);
  }

  releaseProcess();
  emit queryWriteFormatsFinished(result);
  return;
}

bool OBProcess::convert(const QByteArray& input, const QString& inFormat,
                        const QString& outFormat, const QStringList& options)
{
  if (!tryLockProcess()) {
    qWarning() << "OBProcess::convert: process already in use.";
    return false;
  }

  QStringList realOptions;
  realOptions << QString("-i%1").arg(inFormat) << QString("-o%1").arg(outFormat)
              << options;

  executeObabel(realOptions, this, SLOT(convertPrepareOutput()), input);
  return true;
}

bool OBProcess::convert(const QString& filename, const QString& inFormat,
                        const QString& outFormat, const QStringList& options)
{
  if (!tryLockProcess()) {
    qWarning() << "OBProcess::convert: process already in use.";
    return false;
  }

  QStringList realOptions;
  realOptions << QString("-i%1").arg(inFormat) << filename
              << QString("-o%1").arg(outFormat) << options;

  executeObabel(realOptions, this, SLOT(convertPrepareOutput()));
  return true;
}

void OBProcess::convertPrepareOutput()
{
  if (m_aborted) {
    releaseProcess();
    return;
  }

  // Keep this empty if an error occurs:
  QByteArray output;

  // Check for errors.
  QString errorOutput = QString::fromLatin1(m_process->readAllStandardError());
  QRegularExpression errorChecker("\\b0 molecules converted\\b"
                                  "|"
                                  "obabel: cannot read input format!");
  if (!errorOutput.contains(errorChecker)) {
    if (m_process->exitStatus() == QProcess::NormalExit)
      output = m_process->readAllStandardOutput();
  }

  /// Print any meaningful warnings @todo This should go to a log at some point.
  if (!errorOutput.isEmpty() && errorOutput != "1 molecule converted\n")
    qWarning() << m_obabelExecutable << " stderr:\n" << errorOutput;

  emit convertFinished(output);
  releaseProcess();
}

bool OBProcess::queryForceFields()
{
  if (!tryLockProcess()) {
    qWarning() << "OBProcess::queryForceFields(): process already in use.";
    return false;
  }

  QStringList options;
  options << "-L"
          << "forcefields";

  executeObabel(options, this, SLOT(queryForceFieldsPrepare()));
  return true;
}

void OBProcess::queryForceFieldsPrepare()
{
  if (m_aborted) {
    releaseProcess();
    return;
  }

  QMultiMap<QString, QString> result;

  QString output = QString::fromLatin1(m_process->readAllStandardOutput());

  QRegularExpression parser(R"(([^\s]+)\s+(\S[^\n]*[^\n\.]+)\.?\n)");
  QRegularExpressionMatch match;
  int pos = 0;
  while ((match = parser.match(output, pos)).hasMatch()) {
    QString key = match.captured(1);
    QString desc = match.captured(2);
    result.insertMulti(key, desc);
    pos = match.capturedEnd(0);
  }

  releaseProcess();
  emit queryForceFieldsFinished(result);
}

bool OBProcess::queryCharges()
{
  if (!tryLockProcess()) {
    qWarning() << "OBProcess::queryCharges(): process already in use.";
    return false;
  }

  QStringList options;
  options << "-L"
          << "charges";

  executeObabel(options, this, SLOT(queryChargesPrepare()));
  return true;
}

void OBProcess::queryChargesPrepare()
{
  if (m_aborted) {
    releaseProcess();
    return;
  }

  QMultiMap<QString, QString> result;

  QString output = QString::fromLatin1(m_process->readAllStandardOutput());

  QRegularExpression parser(R"(([^\s]+)\s+(\S[^\n]*[^\n\.]+)\.?\n)");
  QRegularExpressionMatch match;
  int pos = 0;
  while ((match = parser.match(output, pos)).hasMatch()) {
    QString key = match.captured(1);
    QString desc = match.captured(2);
    result.insertMulti(key, desc);
    pos = match.capturedEnd(0);
  }

  releaseProcess();
  emit queryChargesFinished(result);
}

bool OBProcess::calculateCharges(const QByteArray& mol,
                                 const std::string& format,
                                 const std::string& type)
{
  if (!tryLockProcess()) {
    qWarning() << "OBProcess::calculateCharges(): process already in use.";
    return false;
  }

  QStringList realOptions;

  if (format == "cjson") {
    realOptions << "-icjson";
  } else {
    realOptions << "-icml";
  }
  realOptions << "-onul" // ignore the output
              << "--partialcharge" << type.c_str() << "--print";

  // Start the optimization
  executeObabel(realOptions, this, SLOT(chargesPrepareOutput()), mol);
  return true;
}

void OBProcess::chargesPrepareOutput()
{
  if (m_aborted) {
    releaseProcess();
    return;
  }

  // Keep this empty if an error occurs:
  QByteArray output;

  // Check for errors.
  QString errorOutput = QString::fromLatin1(m_process->readAllStandardError());
  QRegularExpression errorChecker("\\b0 molecules converted\\b"
                                  "|"
                                  "obabel: cannot read input format!");
  if (!errorOutput.contains(errorChecker)) {
    if (m_process->exitStatus() == QProcess::NormalExit)
      output = m_process->readAllStandardOutput();
  }

  /// Print any meaningful warnings @todo This should go to a log at some point.
  if (!errorOutput.isEmpty() && errorOutput != "1 molecule converted\n")
    qWarning() << m_obabelExecutable << " stderr:\n" << errorOutput;

  // Convert the output line-by-line to charges
  Core::Array<double> charges;
  QTextStream stream(output);
  QString line;
  while (stream.readLineInto(&line)) {
    bool ok;
    double charge = line.toDouble(&ok);
    if (!ok)
      break;

    charges.push_back(charge);
  }

  emit chargesFinished(charges);
  releaseProcess();
}

bool OBProcess::optimizeGeometry(const QByteArray& mol,
                                 const QStringList& options,
                                 const std::string format)
{
  if (!tryLockProcess()) {
    qWarning() << "OBProcess::optimizeGeometry(): process already in use.";
    return false;
  }

  QStringList realOptions;
  if (format == "cjson") {
    realOptions << "-icjson"
                << "-ocjson";
  } else {
    realOptions << "-icml"
                << "-ocml";
  }
  realOptions << "--minimize"
              << "--noh" // new in OB 3.0.1
              << "--log" << options;

  // We'll need to read the log (printed to stderr) to update progress
  connect(m_process, SIGNAL(readyReadStandardError()),
          SLOT(optimizeGeometryReadLog()));

  // Initialize the log reader ivars
  m_optimizeGeometryLog.clear();
  m_optimizeGeometryMaxSteps = -1;

  // Start the optimization
  executeObabel(realOptions, this, SLOT(optimizeGeometryPrepare()), mol);
  return true;
}

bool OBProcess::generateConformers(const QByteArray& mol,
                                   const QStringList& options,
                                   const std::string format)
{
  if (!tryLockProcess()) {
    qWarning() << "OBProcess::generateConformers(): process already in use.";
    return false;
  }

  QStringList realOptions;
  if (format == "cjson") {
    // The cjson writer stores every conformer in one document, as 3dSets.
    realOptions << "-icjson"
                << "-ocjson";
  } else {
    // The CML writer has no conformer support, so it would only give us the
    // lowest-energy geometry. --writeconformers writes each conformer as its
    // own <molecule> instead, which the CML reader turns into coordinate sets.
    // Open Babel gained cjson after 3.1.1, so this is the path most users take.
    realOptions << "-icml"
                << "-ocml"
                << "--writeconformers";
  }
  // Open Babel's genetic algorithm search logs to stdout rather than stderr
  // (OBConformerSearch defaults m_logstream to std::cout and the --conformer
  // operation never redirects it), so anything written to stdout arrives
  // interleaved with the molecule. Collect the molecule in a file instead --
  // that keeps the two apart on every Open Babel release.
  clearConformerOutputFile();
  m_conformerOutputFile =
    new QTemporaryFile(QDir::tempPath() + "/avogadro_conformers_XXXXXX." +
                         QString::fromStdString(format),
                       this);
  if (!m_conformerOutputFile->open()) {
    qWarning() << "OBProcess::generateConformers(): could not create a "
                  "temporary file for the conformer search output.";
    clearConformerOutputFile();
    releaseProcess();
    return false;
  }
  // Close it so obabel can write to it, but keep the object alive: it owns the
  // file name, and removes the file when it is destroyed.
  m_conformerOutputFile->close();

  realOptions << "-O" << m_conformerOutputFile->fileName();

  realOptions << "--conformer"
              << "--noh" // new in OB 3.0.1
              << "--log" << options;

  // We'll need to read the log (printed to stderr) to update progress
  connect(m_process, SIGNAL(readyReadStandardError()),
          SLOT(conformerReadLog()));

  // Initialize the log reader ivars
  m_optimizeGeometryLog.clear();
  m_maxConformers = -1;

  // Start the optimization
  executeObabel(realOptions, this, SLOT(conformerPrepare()), mol);
  return true;
}

void OBProcess::optimizeGeometryPrepare()
{
  if (m_aborted) {
    releaseProcess();
    return;
  }

  QByteArray result = m_process->readAllStandardOutput();

  releaseProcess();
  emit optimizeGeometryFinished(result);
}

void OBProcess::conformerPrepare()
{
  if (m_aborted) {
    clearConformerOutputFile();
    releaseProcess();
    return;
  }

  // The molecules were written to a file rather than stdout, so that the
  // genetic algorithm's log could not corrupt them.
  QByteArray result;
  if (m_conformerOutputFile) {
    QFile output(m_conformerOutputFile->fileName());
    if (output.open(QIODevice::ReadOnly))
      result = output.readAll();
    else
      qWarning() << "OBProcess::conformerPrepare(): could not read the "
                    "conformer search output from"
                 << m_conformerOutputFile->fileName();
  }
  clearConformerOutputFile();

  releaseProcess();
  emit generateConformersFinished(result);
}

void OBProcess::clearConformerOutputFile()
{
  delete m_conformerOutputFile;
  m_conformerOutputFile = nullptr;
}

void OBProcess::optimizeGeometryReadLog()
{
  // Append the current stderr to the log
  m_optimizeGeometryLog +=
    QString::fromLatin1(m_process->readAllStandardError());

  // Search for the maximum number of steps if we haven't found it yet
  if (m_optimizeGeometryMaxSteps < 0) {
    QRegularExpression maxStepsParser("\nSTEPS = ([0-9]+)\n\n");
    QRegularExpressionMatch match;
    if ((match = maxStepsParser.match(m_optimizeGeometryLog)).hasMatch()) {
      m_optimizeGeometryMaxSteps = match.captured(1).toInt();
      emit optimizeGeometryStatusUpdate(0, m_optimizeGeometryMaxSteps, 0.0,
                                        0.0);
    }
  }

  // Emit the last printed step
  if (m_optimizeGeometryMaxSteps >= 0) {
    QRegularExpression lastStepParser(
      R"(\n\s*([0-9]+)\s+([-0-9.]+)\s+([-0-9.]+)\n)");
    QRegularExpressionMatchIterator matchIterator =
      lastStepParser.globalMatch(m_optimizeGeometryLog);
    QRegularExpressionMatch lastMatch;
    while (matchIterator.hasNext()) {
      lastMatch = matchIterator.next(); // Capture the last match
    }
    if (lastMatch.hasMatch()) {
      int step = lastMatch.captured(1).toInt();
      double energy = lastMatch.captured(2).toDouble();
      double lastEnergy = lastMatch.captured(3).toDouble();
      emit optimizeGeometryStatusUpdate(step, m_optimizeGeometryMaxSteps,
                                        energy, lastEnergy);
    }
  }
}

void OBProcess::conformerReadLog()
{
  // Append the current stderr to the log
  // (we're grabbing the log from the geometry optimization)
  m_optimizeGeometryLog +=
    QString::fromLatin1(m_process->readAllStandardError());

  // Search for the maximum number of steps if we haven't found it yet
  if (m_optimizeGeometryMaxSteps < 0) {
    QRegularExpression maxStepsParser("\nSTEPS = ([0-9]+)\n\n");
    QRegularExpressionMatch match;
    if ((match = maxStepsParser.match(m_optimizeGeometryLog)).hasMatch()) {
      m_optimizeGeometryMaxSteps = match.captured(1).toInt();
      emit optimizeGeometryStatusUpdate(0, m_optimizeGeometryMaxSteps, 0.0,
                                        0.0);
    }
  }

  // Emit the last printed step
  if (m_optimizeGeometryMaxSteps >= 0) {
    QRegularExpression lastStepParser(
      R"(\n\s*([0-9]+)\s+([-0-9.]+)\s+([-0-9.]+)\n)");
    QRegularExpressionMatch match;
    if ((match = lastStepParser.match(m_optimizeGeometryLog)).hasMatch()) {
      int step = match.captured(1).toInt();
      double energy = match.captured(2).toDouble();
      double lastEnergy = match.captured(3).toDouble();
      emit optimizeGeometryStatusUpdate(step, m_optimizeGeometryMaxSteps,
                                        energy, lastEnergy);
    }
  }
}

void OBProcess::executeObabel(const QStringList& options, QObject* receiver,
                              const char* slot, const QByteArray& obabelStdin)
{
  // Setup exit handler
  if (receiver) {
    connect(m_process, SIGNAL(finished(int)), receiver, slot);
    connect(m_process, SIGNAL(errorOccurred(QProcess::ProcessError)), receiver,
            slot);
    connect(m_process, SIGNAL(errorOccurred(QProcess::ProcessError)), this,
            SLOT(obError()));
  }

  // Start process
#ifndef NDEBUG
  qDebug() << "OBProcess::executeObabel: "
              "Running"
           << m_obabelExecutable << options.join(" ");
#endif
  m_process->start(m_obabelExecutable, options);
  if (!obabelStdin.isNull()) {
    m_process->write(obabelStdin);
    m_process->closeWriteChannel();
  }
}

void OBProcess::resetState()
{
  m_aborted = false;
  m_process->disconnect(this);
  disconnect(m_process);
  connect(this, SIGNAL(aborted()), m_process, SLOT(kill()));
}

} // namespace Avogadro::QtPlugins
