/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "forcefield.h"
#include "forcefielddialog.h"
#include "obmmenergy.h"
#include "scriptenergy.h"

#ifdef BUILD_GPL_PLUGINS
#include "obenergy.h"
#endif

#include <QtCore/QDebug>
#include <QtCore/QScopedPointer>
#include <QtCore/QSettings>
#include <QtCore/QThread>
#include <QtCore/QTimer>

#include <QAction>
#include <QtWidgets/QMessageBox>

#include <QProgressDialog>

#include <avogadro/qtgui/avogadropython.h>
#include <avogadro/qtgui/calcworker.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/qtgui/utilities.h>

#include <avogadro/qtgui/packagemanager.h>

#include <avogadro/calc/energymanager.h>
#include <avogadro/calc/energyoptimizer.h>
#include <avogadro/calc/lennardjones.h>

namespace Avogadro {
namespace QtPlugins {

using Avogadro::Calc::EnergyCalculator;
using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::RWMolecule;

const int energyAction = 0;
const int optimizeAction = 1;
const int configureAction = 2;
const int freezeAction = 3;
const int unfreezeAction = 4;
const int constraintAction = 5;
const int forcesAction = 6;
const int fuseAction = 7;
const int unfuseAction = 8;

Forcefield::Forcefield(QObject* parent_)
  : ExtensionPlugin(parent_), m_method(nullptr)
{
  QSettings settings;
  settings.beginGroup("forcefield");
  m_autodetect = settings.value("autodetect", true).toBool();
  m_methodName = settings.value("forcefield", "LJ").toString().toStdString();
  m_nSteps = settings.value("steps", 10).toInt();
  m_maxSteps = settings.value("maxSteps", 250).toInt();
  m_tolerance = settings.value("tolerance", 1.0e-4).toDouble();
  m_gradientTolerance = settings.value("gradientTolerance", 1.0e-4).toDouble();
  m_modelUserOptions = settings.value("modelUserOptions").toMap();
  settings.endGroup();

  QAction* action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Optimize Geometry"));
  action->setShortcut(QKeySequence("Ctrl+Alt+O"));
  action->setData(optimizeAction);
  action->setProperty("menu priority", 920);
  connect(action, SIGNAL(triggered()), SLOT(optimize()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Energy")); // calculate energy
  action->setData(energyAction);
  action->setProperty("menu priority", 910);
  connect(action, SIGNAL(triggered()), SLOT(energy()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Forces")); // calculate gradients
  action->setData(forcesAction);
  action->setProperty("menu priority", 910);
  connect(action, SIGNAL(triggered()), SLOT(forces()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Configure…"));
  action->setData(configureAction);
  action->setProperty("menu priority", 900);
  connect(action, SIGNAL(triggered()), SLOT(showDialog()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setSeparator(true);
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Freeze Selected Atoms"));
  action->setData(freezeAction);
  action->setProperty("menu priority", 790);
  connect(action, SIGNAL(triggered()), SLOT(freezeSelected()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Freeze X", "freeze x-axis of selected atoms"));
  action->setData(unfreezeAction);
  action->setProperty("menu priority", 788);
  connect(action, SIGNAL(triggered()), SLOT(freezeX()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Freeze Y", "freeze y-axis of selected atoms"));
  action->setData(unfreezeAction);
  action->setProperty("menu priority", 787);
  connect(action, SIGNAL(triggered()), SLOT(freezeY()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Freeze Z", "freeze z-axis of selected atoms"));
  action->setData(unfreezeAction);
  action->setProperty("menu priority", 786);
  connect(action, SIGNAL(triggered()), SLOT(freezeZ()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Unfreeze Selected Atoms"));
  action->setData(unfreezeAction);
  action->setProperty("menu priority", 780);
  connect(action, SIGNAL(triggered()), SLOT(unfreezeSelected()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(
    tr("Fuse Selected Atoms", "freeze atomic distances / glue atoms together"));
  action->setData(fuseAction);
  action->setProperty("menu priority", 770);
  connect(action, SIGNAL(triggered()), SLOT(fuseSelected()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Unfuse Selected Atoms",
                     "freeze atomic distances / glue atoms together"));
  action->setData(unfuseAction);
  action->setProperty("menu priority", 760);
  connect(action, SIGNAL(triggered()), SLOT(unfuseSelected()));
  m_actions.push_back(action);

  // initialize the calculators

  // prefer to use Python interface scripts if available
  refreshScripts();

  // Connect to PackageManager for pyproject.toml-based packages
  auto* pm = QtGui::PackageManager::instance();
  connect(pm, &QtGui::PackageManager::featureRegistered, this,
          &Forcefield::registerFeature);
  connect(pm, &QtGui::PackageManager::featureRemoved, this,
          &Forcefield::unregisterFeature);

  // add the openbabel calculators in case they don't exist
#ifdef BUILD_GPL_PLUGINS
  // These directly use Open Babel and are fast
  qDebug() << " registering GPL plugins";

  // sanity check, try an energy for a (bad) water molecule
  Molecule water;
  water.addAtom(6);
  water.addAtom(1);
  water.addAtom(1);
  water.addBond(0, 1);
  water.addBond(0, 2);

  auto ob = new OBEnergy("MMFF94");
  ob->setMolecule(&water);
  Eigen::VectorXd positions(3 * 3);
  positions << 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0;
  Real energy = ob->value(positions);
  if (energy != 0.0) {
    Calc::EnergyManager::registerModel(ob);
  } else {
    delete ob;
  }

  // check GAFF
  ob = new OBEnergy("GAFF");
  ob->setMolecule(&water);
  energy = ob->value(positions);
  if (energy != 0.0) {
    Calc::EnergyManager::registerModel(ob);
  } else {
    delete ob;
  }
#else
  // These call obmm and can be slower
  qDebug() << " registering obmm plugins";
  Calc::EnergyManager::registerModel(new OBMMEnergy("MMFF94"));
  Calc::EnergyManager::registerModel(new OBMMEnergy("GAFF"));
#endif
}

Forcefield::~Forcefield()
{
  cleanupWorker();
}

QList<QAction*> Forcefield::actions() const
{
  return m_actions;
}

QStringList Forcefield::menuPath(QAction* action) const
{
  QStringList path;
  if (action->data().toInt() == optimizeAction)
    path << tr("&Extensions");
  else
    path << tr("&Extensions") << tr("&Calculate");

  return path;
}

void Forcefield::showDialog()
{
  QStringList forceFields;
  QVariantMap modelUserOptionSchemas;
  auto list =
    Calc::EnergyManager::instance().identifiersForMolecule(*m_molecule);
  for (auto option : list) {
    const QString optionName = option.c_str();
    forceFields << optionName;

    QScopedPointer<EnergyCalculator> model(
      Calc::EnergyManager::instance().model(option));
    if (model) {
      const std::string schema = model->userOptions();
      if (!schema.empty())
        modelUserOptionSchemas.insert(optionName,
                                      QString::fromStdString(schema));
    }
  }

  QSettings settings;
  QVariantMap options;
  options["forcefield"] = m_methodName.c_str();
  options["nSteps"] = m_nSteps;
  options["maxSteps"] = m_maxSteps;
  options["tolerance"] = m_tolerance;
  options["gradientTolerance"] = m_gradientTolerance;
  options["autodetect"] = m_autodetect;
  options["modelUserOptions"] = m_modelUserOptions;
  options["modelUserOptionsSchemas"] = modelUserOptionSchemas;

  QVariantMap results = ForceFieldDialog::prompt(
    nullptr, forceFields, options, recommendedForceField().c_str());

  if (!results.isEmpty()) {
    // update settings
    settings.beginGroup("forcefield");
    m_methodName = results["forcefield"].toString().toStdString();
    settings.setValue("forcefield", m_methodName.c_str());

    m_maxSteps = results["maxSteps"].toInt();
    settings.setValue("maxSteps", m_maxSteps);
    m_tolerance = results["tolerance"].toDouble();
    settings.setValue("tolerance", m_tolerance);
    m_gradientTolerance = results["gradientTolerance"].toDouble();
    settings.setValue("gradientTolerance", m_gradientTolerance);
    m_autodetect = results["autodetect"].toBool();
    settings.setValue("autodetect", m_autodetect);
    m_modelUserOptions = results["modelUserOptions"].toMap();
    settings.setValue("modelUserOptions", m_modelUserOptions);
    settings.endGroup();
  }
  setupMethod();
}

void Forcefield::setMolecule(QtGui::Molecule* mol)
{
  if (mol == nullptr || m_molecule == mol)
    return;

  m_molecule = mol;

  // TODO: connect to molecule changes, e.g. selection
  // connect(m_molecule, SIGNAL(changed(uint)), SLOT(updateActions()));
}

void Forcefield::updateActions()
{
  if (m_molecule == nullptr)
    return;

  bool noSelection = m_molecule->isSelectionEmpty();
  foreach (QAction* action, m_actions) {
    switch (action->data().toInt()) {
      case freezeAction:
      case unfreezeAction:
      case fuseAction:
      case unfuseAction:
        action->setEnabled(!noSelection);
        break;
      default:
        break;
    }
  }
}

void Forcefield::setupMethod()
{
  if (m_molecule == nullptr)
    return; // nothing to do until its set

  if (m_autodetect)
    m_methodName = recommendedForceField();

  // check if m_methodName even exists (e.g., saved preference)
  // or if that method doesn't work for this (e.g., unit cell, etc.)
  auto list =
    Calc::EnergyManager::instance().identifiersForMolecule(*m_molecule);
  bool found = false;
  for (auto option : list) {
    if (option == m_methodName) {
      found = true;
      break;
    }
  }

  // fall back to recommended if not found (LJ will always work)
  if (!found) {
    m_methodName = recommendedForceField();
  }

  if (m_method != nullptr) {
    delete m_method; // delete the previous one
  }
  m_method = Calc::EnergyManager::instance().model(m_methodName);

  if (m_method != nullptr) {
    const QString methodId = QString::fromStdString(m_methodName);
    const QString modelOptions = m_modelUserOptions.value(methodId).toString();
    if (!modelOptions.trimmed().isEmpty() &&
        !m_method->setUserOptions(modelOptions.toStdString())) {
      qWarning() << "Failed to parse user options for force field" << methodId;
    }
    m_method->setMolecule(m_molecule);
  }
}

void Forcefield::setupConstraints()
{
  if (m_molecule == nullptr || m_method == nullptr)
    return; // nothing to do

  auto n = m_molecule->atomCount();

  // first set the frozen coordinate mask
  auto mask = m_molecule->frozenAtomMask();
  if (mask.rows() != static_cast<Eigen::Index>(3 * n)) {
    // set the mask to all ones
    mask = Eigen::VectorXd::Ones(static_cast<Eigen::Index>(3 * n));
  }
  m_method->setMolecule(m_molecule);
  m_method->setMask(mask);

  // now set the constraints
  m_method->setConstraints(m_molecule->constraints());
}

void Forcefield::cleanupWorker()
{
  if (m_workerThread) {
    m_workerThread->quit();
    m_workerThread->wait(5000);
    // deleteLater handles the worker and thread via finished() connections
    m_workerThread = nullptr;
    m_worker = nullptr;
  }
  if (m_progressDialog) {
    m_progressDialog->hide();
    m_progressDialog->deleteLater();
    m_progressDialog = nullptr;
  }
  m_optimizing = false;
}

void Forcefield::startWorker()
{
  cleanupWorker();

  auto n = m_molecule->atomCount();

  // Build the frozen atom mask
  auto mask = m_molecule->frozenAtomMask();
  if (mask.rows() != static_cast<Eigen::Index>(3 * n))
    mask = Eigen::VectorXd::Ones(static_cast<Eigen::Index>(3 * n));

  auto constraints = m_molecule->constraints();

  // Create a fresh calculator clone for the worker thread
  auto* calc = Calc::EnergyManager::instance().model(m_methodName);
  if (calc == nullptr)
    return;

  // Apply user options to the clone
  const QString methodId = QString::fromStdString(m_methodName);
  const QString modelOptions = m_modelUserOptions.value(methodId).toString();
  if (!modelOptions.trimmed().isEmpty())
    calc->setUserOptions(modelOptions.toStdString());

  // Create a molecule snapshot (topology only, positions set separately)
  Core::Molecule snapshot = static_cast<const Core::Molecule&>(*m_molecule);

  // Set up the worker thread
  m_workerThread = new QThread(this);
  m_worker = new QtGui::CalcWorker();
  m_worker->moveToThread(m_workerThread);

  connect(m_workerThread, &QThread::finished, m_worker, &QObject::deleteLater);
  m_workerThread->start();

  // Store args for initCalculator — caller must connect signals first,
  // then invoke initCalculator via sendInitCalculator().
  m_pendingCalc = calc;
  m_pendingSnapshot = snapshot;
  m_pendingMask = mask;
  m_pendingConstraints = constraints;
}

void Forcefield::sendInitCalculator()
{
  if (!m_worker || !m_pendingCalc)
    return;

  QMetaObject::invokeMethod(
    m_worker, "initCalculator", Qt::QueuedConnection,
    Q_ARG(Avogadro::Calc::EnergyCalculator*, m_pendingCalc),
    Q_ARG(Avogadro::Core::Molecule, m_pendingSnapshot),
    Q_ARG(Eigen::VectorXd, m_pendingMask),
    Q_ARG(std::vector<Avogadro::Core::Constraint>, m_pendingConstraints));
  m_pendingCalc = nullptr;
}

void Forcefield::optimize()
{
  if (m_molecule == nullptr || m_optimizing)
    return;

  if (m_method == nullptr)
    setupMethod();
  if (m_method == nullptr)
    return;

  if (!m_molecule->atomCount()) {
    QMessageBox::information(nullptr, tr("Avogadro"),
                             tr("No atoms provided for optimization"));
    return;
  }

  m_currentStep = 0;

  // merge all coordinate updates into one undo step
  m_molecule->undoMolecule()->setInteractive(true);

  // Set up optimization options
  m_optOptions.algorithm = Calc::OptimizationAlgorithm::Lbfgs;
  m_optOptions.chunkIterations = 5;

  // Snapshot current positions
  auto n = m_molecule->atomCount();
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  Eigen::Map<Eigen::VectorXd> map(pos[0].data(), 3 * n);
  m_lastPositions = map;
  m_lastEnergy = 0.0;

  // Start the worker first (calls cleanupWorker() which resets m_optimizing)
  startWorker();

  // Set m_optimizing AFTER startWorker, since cleanupWorker resets it
  m_optimizing = true;

  // Create progress dialog
  int totalChunks = static_cast<int>(m_maxSteps / m_optOptions.chunkIterations);
  m_progressDialog =
    new QProgressDialog(tr("Optimize Geometry"), tr("Cancel"), 0, totalChunks);
  m_progressDialog->setWindowModality(Qt::WindowModal);
  m_progressDialog->setMinimumDuration(0);
  m_progressDialog->show();

  connect(m_progressDialog, &QProgressDialog::canceled, this, [this]() {
    if (m_worker)
      m_worker->cancel();
    cleanupWorker();
    if (m_molecule)
      m_molecule->undoMolecule()->setInteractive(false);
  });

  connect(m_worker, &QtGui::CalcWorker::calculatorReady, this,
          &Forcefield::onWorkerReady);
  connect(m_worker, &QtGui::CalcWorker::optimizeFinished, this,
          &Forcefield::onOptimizeChunkDone);

  sendInitCalculator();
}

void Forcefield::onWorkerReady()
{
  if (!m_optimizing || !m_worker)
    return;

  // Send the first optimization chunk
  QMetaObject::invokeMethod(
    m_worker, "runOptimizeChunk", Qt::QueuedConnection,
    Q_ARG(Eigen::VectorXd, m_lastPositions),
    Q_ARG(Avogadro::Calc::OptimizationOptions, m_optOptions));
}

void Forcefield::onOptimizeChunkDone(Eigen::VectorXd positions,
                                     Eigen::VectorXd gradient, double energy,
                                     bool converged)
{
  if (!m_optimizing || m_molecule == nullptr)
    return;

  auto n = m_molecule->atomCount();
  m_currentStep++;

  if (m_progressDialog) {
    m_progressDialog->setValue(m_currentStep);
    m_progressDialog->setLabelText(
      tr("Energy: %L1", "force field energy").arg(energy, 0, 'f', 3));
  }

#ifndef NDEBUG
  qDebug() << " optimize " << m_currentStep << energy
           << " gradNorm: " << gradient.norm();
#endif

  // Update coordinates if valid
  if (std::isfinite(energy) && positions.allFinite()) {
    Core::Array<Vector3> pos(n);
    Eigen::Map<Eigen::VectorXd>(pos[0].data(), 3 * n) = positions;

    Core::Array<Vector3> forces(n);
    if (gradient.size() == 3 * static_cast<Eigen::Index>(n))
      Eigen::Map<Eigen::VectorXd>(forces[0].data(), 3 * n) = -gradient;

    m_molecule->undoMolecule()->setAtomPositions3d(pos,
                                                   tr("Optimize Geometry"));
    m_molecule->setForceVectors(forces);
    Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Modified;
    m_molecule->emitChanged(changes);

    m_lastPositions = positions;
  } else {
    qDebug() << "Non-finite energy, stopping optimization" << energy;
    converged = true;
  }

  // Check convergence criteria
  bool done = converged;
  if (!done && gradient.size() > 0) {
    if (fabs(gradient.maxCoeff()) < m_gradientTolerance)
      done = true;
    if (m_lastEnergy != 0.0 && fabs(energy - m_lastEnergy) < m_tolerance)
      done = true;
  }

  int totalChunks = static_cast<int>(m_maxSteps / m_optOptions.chunkIterations);
  if (m_currentStep >= totalChunks)
    done = true;

  m_lastEnergy = energy;

  if (done || (m_progressDialog && m_progressDialog->wasCanceled())) {
    // Optimization complete
    m_molecule->undoMolecule()->setInteractive(false);
    cleanupWorker();
  } else {
    // Request next chunk
    QMetaObject::invokeMethod(
      m_worker, "runOptimizeChunk", Qt::QueuedConnection,
      Q_ARG(Eigen::VectorXd, m_lastPositions),
      Q_ARG(Avogadro::Calc::OptimizationOptions, m_optOptions));
  }
}

void Forcefield::energy()
{
  if (m_molecule == nullptr || m_optimizing)
    return;

  if (m_method == nullptr)
    setupMethod();
  if (m_method == nullptr)
    return;

  auto n = m_molecule->atomCount();
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  Eigen::Map<Eigen::VectorXd> map(pos[0].data(), 3 * n);
  Eigen::VectorXd positions = map;

  startWorker();

  connect(
    m_worker, &QtGui::CalcWorker::calculatorReady, this, [this, positions]() {
      QMetaObject::invokeMethod(m_worker, "runEvaluate", Qt::QueuedConnection,
                                Q_ARG(Eigen::VectorXd, positions),
                                Q_ARG(bool, false));
    });
  connect(m_worker, &QtGui::CalcWorker::evaluateFinished, this,
          &Forcefield::onEnergyDone);

  sendInitCalculator();
}

void Forcefield::onEnergyDone(Eigen::VectorXd gradient, double energy)
{
  Q_UNUSED(gradient);
  QString msg(tr("%1 Energy = %L2").arg(m_methodName.c_str()).arg(energy));
  cleanupWorker();
  QMessageBox::information(nullptr, tr("Avogadro"), msg);
}

void Forcefield::forces()
{
  if (m_molecule == nullptr || m_optimizing)
    return;

  if (m_method == nullptr)
    setupMethod();
  if (m_method == nullptr)
    return;

  auto n = m_molecule->atomCount();
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  Eigen::Map<Eigen::VectorXd> map(pos[0].data(), 3 * n);
  Eigen::VectorXd positions = map;

  startWorker();

  connect(
    m_worker, &QtGui::CalcWorker::calculatorReady, this, [this, positions]() {
      QMetaObject::invokeMethod(m_worker, "runGradient", Qt::QueuedConnection,
                                Q_ARG(Eigen::VectorXd, positions));
    });
  connect(m_worker, &QtGui::CalcWorker::evaluateFinished, this,
          &Forcefield::onForcesDone);

  sendInitCalculator();
}

void Forcefield::onForcesDone(Eigen::VectorXd gradient, double energy)
{
  Q_UNUSED(energy);

  if (m_molecule == nullptr) {
    cleanupWorker();
    return;
  }

  auto n = m_molecule->atomCount();

  Core::Array<Vector3> forces(n);
  if (gradient.size() == 3 * static_cast<Eigen::Index>(n))
    Eigen::Map<Eigen::VectorXd>(forces[0].data(), 3 * n) = -gradient;

  m_molecule->setForceVectors(forces);
  Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Modified;
  m_molecule->emitChanged(changes);

  QString msg(
    tr("%1 Force Norm = %L2").arg(m_methodName.c_str()).arg(gradient.norm()));
  cleanupWorker();
  QMessageBox::information(nullptr, tr("Avogadro"), msg);
}

std::string Forcefield::recommendedForceField() const
{
  // if we have a unit cell, we need to use the LJ calculator
  // (implementing something better would be nice)
  if (m_molecule == nullptr || m_molecule->unitCell() != nullptr)
    return "LJ";

  // otherwise, let's see what identifers are returned
  auto list =
    Calc::EnergyManager::instance().identifiersForMolecule(*m_molecule);
  if (list.empty())
    return "LJ"; // this will always work

  // iterate to see what we have
  std::string bestOption;
  for (auto option : list) {
    // GAFF is better than MMFF94 which is better than UFF
    if (option == "UFF" && bestOption != "GAFF" && bestOption != "MMFF94")
      bestOption = option;
    if (option == "MMFF94" && bestOption != "GAFF")
      bestOption = option;
  }
  if (!bestOption.empty())
    return bestOption;
  else
    return "LJ"; // this will always work
}

void Forcefield::freezeSelected()
{
  if (m_molecule == nullptr || m_molecule->isSelectionEmpty())
    return; // nothing to do until there's a valid selection

  auto numAtoms = m_molecule->atomCount();
  // now freeze the specified atoms
  for (Index i = 0; i < numAtoms; ++i) {
    if (m_molecule->atomSelected(i)) {
      m_molecule->setFrozenAtom(i, true);
    }
  }

  m_molecule->emitChanged(QtGui::Molecule::Constraints);
}

void Forcefield::freezeAxis(int axis)
{
  if (m_molecule == nullptr || m_molecule->isSelectionEmpty())
    return; // nothing to do until there's a valid selection

  auto numAtoms = m_molecule->atomCount();
  // now freeze the specified atoms
  for (Index i = 0; i < numAtoms; ++i) {
    if (m_molecule->atomSelected(i)) {
      m_molecule->setFrozenAtomAxis(i, axis, true);
    }
  }

  m_molecule->emitChanged(QtGui::Molecule::Constraints);
}

void Forcefield::freezeX()
{
  freezeAxis(0);
}
void Forcefield::freezeY()
{
  freezeAxis(1);
}
void Forcefield::freezeZ()
{
  freezeAxis(2);
}

void Forcefield::unfreezeSelected()
{
  if (m_molecule == nullptr || m_molecule->isSelectionEmpty())
    return; // nothing to do until there's a valid selection

  auto numAtoms = m_molecule->atomCount();
  // now freeze the specified atoms
  for (Index i = 0; i < numAtoms; ++i) {
    if (m_molecule->atomSelected(i)) {
      m_molecule->setFrozenAtom(i, false);
    }
  }

  m_molecule->emitChanged(QtGui::Molecule::Constraints);
}

void Forcefield::unfuseSelected()
{
  if (m_molecule == nullptr || m_molecule->isSelectionEmpty())
    return; // nothing to do until there's a valid selection

  auto numAtoms = m_molecule->atomCount();
  // now remove constraints between the specified atoms
  for (Index i = 0; i < numAtoms; ++i) {
    if (m_molecule->atomSelected(i)) {
      for (Index j = i + 1; j < numAtoms; ++j) {
        if (m_molecule->atomSelected(j)) {
          m_molecule->removeConstraint(i, j);
        }
      }
    }
  }

  m_molecule->emitChanged(QtGui::Molecule::Constraints);
}

void Forcefield::fuseSelected()
{
  if (m_molecule == nullptr || m_molecule->isSelectionEmpty())
    return; // nothing to do until there's a valid selection

  // loop through all selected atom pairs
  auto numAtoms = m_molecule->atomCount();
  for (Index i = 0; i < numAtoms; ++i) {
    if (m_molecule->atomSelected(i)) {
      Vector3 iPos = m_molecule->atomPosition3d(i);

      for (Index j = i + 1; j < numAtoms; ++j) {
        if (m_molecule->atomSelected(j)) {
          // both selected, set the constraint
          Vector3 jPos = m_molecule->atomPosition3d(j);
          Real distance = (iPos - jPos).norm();
          Core::Constraint constraint(i, j);
          constraint.setValue(distance);

          m_molecule->addConstraint(constraint);
        }
      }
    }
  }

  m_molecule->emitChanged(QtGui::Molecule::Constraints);
}

void Forcefield::refreshScripts()
{
  unregisterScripts();
  qDeleteAll(m_scripts);
  m_scripts.clear();
  m_packageScripts.clear();
  registerScripts();
}

void Forcefield::unregisterScripts()
{
  for (auto* script : m_scripts)
    Calc::EnergyManager::unregisterModel(script->identifier());
}

void Forcefield::registerScripts()
{
  for (auto* script : m_scripts) {
    qDebug() << " register " << script->identifier().c_str();

    if (!Calc::EnergyManager::registerModel(script->newInstance())) {
      qDebug() << "Could not register model" << script->identifier().c_str()
               << "due to name conflict.";
    }
  }
}

void Forcefield::registerFeature(const QString& type, const QString& packageDir,
                                 const QString& command,
                                 const QString& identifier,
                                 const QVariantMap& metadata)
{
  if (type != QLatin1String("energy-models"))
    return;

  auto* model = new ScriptEnergy();
  model->setPackageInfo(packageDir, command, identifier);
  model->readMetaData(metadata);
  if (model->isValid()) {
    QString managerId = QString::fromStdString(model->identifier());
    auto* newModel = model->newInstance();
    if (!Calc::EnergyManager::registerModel(newModel)) {
      qDebug() << "Could not register energy model" << identifier
               << "due to name conflict.";
      delete newModel;
      delete model;
    } else {
      m_scripts.push_back(model);
      m_packageScripts.insert(QtGui::PackageManager::packageFeatureKey(
                                packageDir, command, identifier),
                              managerId);
    }
  } else {
    delete model;
  }
}

void Forcefield::unregisterFeature(const QString& type,
                                   const QString& packageDir,
                                   const QString& command,
                                   const QString& identifier)
{
  if (type != QLatin1String("energy-models"))
    return;

  const QString featureKey =
    QtGui::PackageManager::packageFeatureKey(packageDir, command, identifier);
  const QList<QString> managerIds = m_packageScripts.values(featureKey);
  if (managerIds.isEmpty())
    return;

  m_packageScripts.remove(featureKey);
  for (const QString& managerId : managerIds) {
    Calc::EnergyManager::unregisterModel(managerId.toStdString());
    for (int i = m_scripts.size() - 1; i >= 0; --i) {
      if (QString::fromStdString(m_scripts[i]->identifier()) == managerId)
        delete m_scripts.takeAt(i);
    }
  }
}

} // namespace QtPlugins
} // namespace Avogadro
