/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "obmmenergy.h"

#include <avogadro/core/molecule.h>

#include <avogadro/io/cmlformat.h>

#include <avogadro/qtgui/utilities.h>

#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QScopedPointer>
#include <QtCore/QThread>
#include <QtCore/QTimer>

namespace Avogadro::QtPlugins {

OBMMEnergy::OBMMEnergy(const std::string& method)
  : m_molecule(nullptr), m_process(nullptr), m_executable(
#if defined(_WIN32)
                                               "obmm.exe"
#else
                                               "obmm"
#endif
                                               ),
    m_identifier(method), m_name(method)
{
  // eventually CJSON might be nice
  m_inputFormat = new Io::CmlFormat;

  if (method == "UFF") {
    m_description = tr("Universal Force Field");
    m_elements.reset();
    for (unsigned int i = 1; i < 102; ++i)
      m_elements.set(i);
  } else if (method == "GAFF") {
    m_description = tr("Generalized Amber Force Field");

    // H, C, N, O, F, P, S, Cl, Br, and I
    m_elements.set(1);
    m_elements.set(6);
    m_elements.set(7);
    m_elements.set(8);
    m_elements.set(9);
    m_elements.set(15);
    m_elements.set(16);
    m_elements.set(17);
    m_elements.set(35);
    m_elements.set(53);
  } else if (method == "MMFF94") {
    m_description = tr("Merck Molecular Force Field 94");
    m_elements.reset();

    // H, C, N, O, F, Si, P, S, Cl, Br, and I
    m_elements.set(1);
    m_elements.set(6);
    m_elements.set(7);
    m_elements.set(8);
    m_elements.set(9);
    m_elements.set(14);
    m_elements.set(15);
    m_elements.set(16);
    m_elements.set(17);
    m_elements.set(35);
    m_elements.set(53);

    // also Fe+2, Fe+3, Li+, Na+, K+, Zn+2, Ca+2, Cu+1, Cu+2, and Mg+2
    m_elements.set(26);
    m_elements.set(3);
    m_elements.set(11);
    m_elements.set(19);
    m_elements.set(20);
    m_elements.set(29);
    m_elements.set(30);
    m_elements.set(12);
  }
}

OBMMEnergy::~OBMMEnergy()
{
  delete m_inputFormat;
  if (m_process != nullptr)
    delete m_process;
}

bool OBMMEnergy::acceptsRadicals() const
{
  // UFF will figure something out
  if (m_identifier == "UFF")
    return true;

  return false;
}

QByteArray OBMMEnergy::writeAndRead(const QByteArray& input)
{
  if (m_process == nullptr || m_process->state() != QProcess::Running)
    return QByteArray();

  QByteArray result, line;
  m_process->write(input + "\n");
  QThread::msleep(1);
  m_process->waitForReadyRead(5);
  while (m_process->canReadLine() && !line.startsWith("command >")) {
    line = m_process->readLine();
    result += line;
  }
  // check if we've really flushed the output
  if (!result.contains("invalid command\n command >")) {
    m_process->write(" \n");
    QThread::msleep(1);
    m_process->waitForReadyRead(5);
    while (m_process->canReadLine()) {
      line = m_process->readLine();
      result += line;
    }
  }
  result += m_process->readAllStandardOutput();
  return result;
}

void OBMMEnergy::setupProcess()
{
  if (m_process != nullptr) {
    m_process->kill();
    delete m_process;
  }

  m_process = new QProcess();

  // Read the AVO_OBMM_EXECUTABLE env var to optionally override the
  // executable used.
  QByteArray obmmExec = qgetenv("AVO_OBMM_EXECUTABLE");
  if (!obmmExec.isEmpty()) {
    m_executable = obmmExec;
  } else {
    // If not overridden, look for an obmm next to the executable.
    QDir baseDir(QCoreApplication::applicationDirPath());
    if (!baseDir.absolutePath().startsWith("/usr/") &&
        QFileInfo(baseDir.absolutePath() + '/' + m_executable).exists()) {
      m_executable = baseDir.absolutePath() + '/' + m_executable;
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

Calc::EnergyCalculator* OBMMEnergy::newInstance() const
{
  return new OBMMEnergy(m_name);
}

void OBMMEnergy::setMolecule(Core::Molecule* mol)
{
  m_molecule = mol;

  // should check if the molecule is valid for this script
  // .. this should never happen, but let's be defensive
  if (mol == nullptr || mol->atomCount() == 0) {
    return; // nothing to do
  }

  setupProcess();

  // start the process
  // we need a tempory file to write the molecule
  // get a temporary filename
  QString tempPath = QDir::tempPath();
  if (!tempPath.endsWith(QDir::separator()))
    tempPath += QDir::separator();
  QString tempPattern = tempPath + "avogadroOBMMXXXXXX.cml";
  m_tempFile.setFileTemplate(tempPattern);
  if (!m_tempFile.open()) {
    // appendError("Error creating temporary file.");
    return;
  }

  // write the molecule
  m_inputFormat->writeFile(m_tempFile.fileName().toStdString(), *mol);
  m_tempFile.close();

  // start the process
  m_process->start(m_executable, QStringList() << m_tempFile.fileName());
  if (!m_process->waitForStarted()) {
    // appendError("Error starting process.");
    qDebug() << "OBMM: Error starting process.";
    return;
  }

  QByteArray input, line, result;
  m_process->waitForReadyRead();
  result.clear();
  while (!result.contains("command >")) {
    result += m_process->readLine();
    if (!m_process->canReadLine())
      break;
  }
  result += m_process->readAllStandardOutput();

  // set the method m_identifier.c_str() +
  input = QByteArray("ff ") + m_identifier.c_str();
  result = writeAndRead(input);

  // okay, we need to write "load <filename>" to the interpreter
  // and then read the response
  input = "load " + m_tempFile.fileName().toLocal8Bit();
  result = writeAndRead(input);
}

Real OBMMEnergy::value(const Eigen::VectorXd& x)
{
  if (m_molecule == nullptr || m_process == nullptr ||
      m_process->state() != QProcess::Running ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return 0.0; // nothing to do

  QByteArray input, result;

  // write the new coordinates and read the energy
  input = "coord\n";
  for (Eigen::Index i = 0; i < x.size(); i += 3) {
    // write as x y z (space separated)
    input += QString::number(x[i]).toUtf8() + " " +
             QString::number(x[i + 1]).toUtf8() + " " +
             QString::number(x[i + 2]).toUtf8() + "\n";
  }

  result = writeAndRead(input);

  // now ask for the energy
  input = "energy\n";
  result = writeAndRead(input);

  // go through lines in result until we see "total energy"
  QStringList lines = QString(result).remove('\r').split('\n');
  double energy = 0.0;
  for (auto line : lines) {
    if (line.contains("total energy =")) {
      QStringList items = line.split(" ", Qt::SkipEmptyParts);
      if (items.size() > 4)
        energy = items[3].toDouble();
    }
  }

  // if method is not GAFF, convert to kJ/mol
  if (m_identifier != "GAFF")
    energy *= Calc::KCAL_TO_KJ;

  energy += constraintEnergies(x);
  return energy; // if conversion fails, returns 0.0
}

void OBMMEnergy::gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (grad.size() != x.size())
    grad.resize(x.size());
  grad.setZero();

  if (m_molecule == nullptr || m_process == nullptr ||
      m_process->state() != QProcess::Running ||
      x.size() != static_cast<Eigen::Index>(3 * m_molecule->atomCount()))
    return;

  // write the new coordinates and read the energy
  QByteArray result, input = "coord\n";
  for (Eigen::Index i = 0; i < x.size(); i += 3) {
    // write as x y z (space separated)
    input += QString::number(x[i]).toUtf8() + " " +
             QString::number(x[i + 1]).toUtf8() + " " +
             QString::number(x[i + 2]).toUtf8() + "\n";
  }

  result = writeAndRead(input);

  // now ask for the energy
  input = "grad";
  result = writeAndRead(input);

  // go through lines in result until we see "gradient "
  QStringList lines = QString(result).remove('\r').split('\n');
  bool readingGradient = false;
  const Eigen::Index atomCount = m_molecule->atomCount();
  Eigen::Index i = 0;
  for (auto line : lines) {
    if (line.contains("gradient")) {
      readingGradient = true;
      continue;
    }
    if (readingGradient) {
      QStringList items = line.split(" ", Qt::SkipEmptyParts);
      if (items.size() == 3) {
        bool xOk = false;
        bool yOk = false;
        bool zOk = false;
        const double gx = items[0].toDouble(&xOk);
        const double gy = items[1].toDouble(&yOk);
        const double gz = items[2].toDouble(&zOk);
        if (!xOk || !yOk || !zOk)
          continue;
        if (i >= atomCount) {
          appendError("OBMM returned more gradient rows than atoms.");
          break;
        }
        grad[3 * i] = gx;
        grad[3 * i + 1] = gy;
        grad[3 * i + 2] = gz;
        ++i;
      }
    }
  }

  if (i != atomCount)
    appendError("OBMM returned an incomplete gradient.");

  grad *= -1; // OpenBabel outputs forces, not grads

  cleanGradients(grad);
  // if method is not GAFF, convert to kJ/mol
  if (m_identifier != "GAFF")
    grad *= Calc::KCAL_TO_KJ;

  constraintGradients(x, grad);
}

} // namespace Avogadro::QtPlugins
