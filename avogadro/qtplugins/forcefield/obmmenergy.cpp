/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "obmmenergy.h"

#include <avogadro/core/molecule.h>

#include <avogadro/io/cmlformat.h>

#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QScopedPointer>
#include <QtCore/QTimer>

namespace Avogadro::QtPlugins {

class OBMMEnergy::ProcessListener : public QObject
{
  Q_OBJECT
public:
  ProcessListener(QProcess* proc)
    : QObject(), m_finished(false), m_process(proc)
  {
  }

  bool waitForOutput(QByteArray output, int msTimeout = 2000)
  {
    connect(m_process, SIGNAL(readyRead()), SLOT(readyRead()));
    if (!wait(msTimeout))
      return false;

    // success!
    output = m_output;
    disconnect(m_process, nullptr, nullptr, nullptr);
    m_finished = false;
    return true;
  }

public slots:
  void readyRead()
  {
    m_finished = true;
    m_output = m_process->readAllStandardOutput();
  }

private:
  bool wait(int msTimeout)
  {
    QTimer timer;
    timer.start(msTimeout);

    while (timer.isActive() && !m_finished)
      qApp->processEvents(QEventLoop::AllEvents, 500);

    return m_finished;
  }

  QProcess* m_process;
  bool m_finished;
  QByteArray m_output;
};

OBMMEnergy::OBMMEnergy(const std::string& method)
  : m_identifier(method), m_name(method), m_process(nullptr),
#if defined(_WIN32)
    m_executable("obmm.exe")
#else
    m_executable("obmm")
#endif
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
  }
}

OBMMEnergy::~OBMMEnergy()
{
  delete m_inputFormat;
  delete m_process;
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
#if defined(_WIN32)
      env.insert("BABEL_DATADIR",
                 QCoreApplication::applicationDirPath() + "/data");
#else
      QDir dir(QCoreApplication::applicationDirPath() + "/../share/openbabel");
      QStringList filters;
      filters << "3.*";
      QStringList dirs = dir.entryList(filters);
      if (dirs.size() == 1) {
        env.insert("BABEL_DATADIR", QCoreApplication::applicationDirPath() +
                                      "/../share/openbabel/" + dirs[0]);
      } else {
        qDebug() << "Error, Open Babel data directory not found.";
      }
      dir.setPath(QCoreApplication::applicationDirPath() + "/../lib/openbabel");
      dirs = dir.entryList(filters);
      if (dirs.size() == 1) {
        env.insert("BABEL_LIBDIR", QCoreApplication::applicationDirPath() +
                                     "/../lib/openbabel/" + dirs[0]);
      } else {
        qDebug() << "Error, Open Babel plugins directory not found.";
      }
#endif
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
  if (mol == nullptr) {
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
    return;
  }
  ProcessListener listener(m_process);
  QByteArray result;
  if (!listener.waitForOutput(result)) {
    // appendError("Error running process.");
    return;
  }
  qDebug() << "OBMM start: " << result;

  // okay, we need to write "load <filename>" to the interpreter
  // and then read the response
  QByteArray input = "load " + m_tempFile.fileName().toLocal8Bit() + "\n";
  m_process->write(input);
  if (!listener.waitForOutput(result)) {
    // appendError("Error running process.");
    return;
  }
  qDebug() << "OBMM: " << result;

  // set the method m_identifier.c_str() +
  input = QByteArray("ff MMFF94\n");
  m_process->write(input);
  if (!listener.waitForOutput(result)) {
    // appendError("Error running process.");
    return;
  }
  qDebug() << "OBMM ff: " << result;

  // check for an energy
  input = QByteArray("energy\n");
  result.clear();
  m_process->write(input);
  result.clear();
  while (!result.contains("command >")) {
    result += m_process->readLine();
  }
  qDebug() << "OBMM energy: " << result;
}

Real OBMMEnergy::value(const Eigen::VectorXd& x)
{
  if (m_molecule == nullptr || m_process == nullptr)
    return 0.0; // nothing to do

  m_process->waitForReadyRead();
  QByteArray result;
  while (!result.contains("command >")) {
    result += m_process->readLine();
  }
  qDebug() << " starting " << result;

  // write the new coordinates and read the energy
  QByteArray input = "coord\n";
  for (Index i = 0; i < x.size(); i += 3) {
    // write as x y z (space separated)
    input += QString::number(x[i]) + " " + QString::number(x[i + 1]) + " " +
             QString::number(x[i + 2]) + "\n";
  }
  input += "\n";

  m_process->write(input);
  m_process->waitForReadyRead();
  result.clear();
  while (!result.contains("command >")) {
    result += m_process->readLine();
  }

  qDebug() << " asking energy " << result << m_process->state();

  // now ask for the energy
  input = "energy\n\n";
  result.clear();
  m_process->write(input);
  m_process->waitForReadyRead();
  while (!result.contains("command >")) {
    result += m_process->readLine();
  }

  qDebug() << "OBMM: " << result;

  // go through lines in result until we see "total energy"
  QStringList lines = QString(result).remove('\r').split('\n');
  double energy = 0.0;
  for (auto line : lines) {
    if (line.contains("total energy =")) {
      qDebug() << " OBMM: " << line;
      QStringList items = line.split(" ", Qt::SkipEmptyParts);
      if (items.size() > 4)
        energy = items[3].toDouble();
    }
  }

  qDebug() << " OBMM: " << energy << " done";

  return energy; // if conversion fails, returns 0.0
}

void OBMMEnergy::gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad)
{
  if (m_molecule == nullptr || m_process == nullptr)
    return;

  EnergyCalculator::gradient(x, grad);
  return;

  qDebug() << "OBMM: gradient";

  // write the new coordinates and read the energy
  QByteArray input = "coord\n";
  for (Index i = 0; i < x.size(); i += 3) {
    // write as x y z (space separated)
    input += QString::number(x[i]) + " " + QString::number(x[i + 1]) + " " +
             QString::number(x[i + 2]) + "\n";
  }

  m_process->write(input);
  qDebug() << "OBMM Grad wrote coords";
  m_process->waitForReadyRead();
  QByteArray result;
  while (m_process->canReadLine()) {
    result += m_process->readLine();
  }

  qDebug() << "OBMM: " << result;

  // now ask for the energy
  input = "grad\n";
  m_process->write(input);
  m_process->waitForReadyRead();
  while (m_process->canReadLine()) {
    result += m_process->readLine();
  }

  qDebug() << "OBMM: " << result;

  // go through lines in result until we see "gradient "
  QStringList lines = QString(result).remove('\r').split('\n');
  bool readingGradient = false;
  unsigned int i = 0;
  for (auto line : lines) {
    if (line.contains("gradient")) {
      readingGradient = true;
      continue;
    }
    if (readingGradient) {
      QStringList items = line.split(" ", Qt::SkipEmptyParts);
      if (items.size() == 3) {
        grad[3 * i] = -1.0 * items[0].toDouble();
        grad[3 * i + 1] = items[1].toDouble();
        grad[3 * i + 2] = items[2].toDouble();
        ++i;
      }
    }
  }

  cleanGradients(grad);
}

} // namespace Avogadro::QtPlugins

#include "obmmenergy.moc"
