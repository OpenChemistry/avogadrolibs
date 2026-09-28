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

#include <avogadro/core/conformerquantity.h>

#include <cmath>

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
const int batchEnergyAction = 9;
const int batchForcesAction = 10;

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

  // Batch actions over every coordinate set (conformers / trajectory frames).
  // Enabled only when more than one coordinate set is present.
  action = new QAction(this);
  action->setEnabled(false);
  action->setText(tr("Energies (All Conformers)"));
  action->setData(batchEnergyAction);
  action->setProperty("menu priority", 906);
  connect(action, SIGNAL(triggered()), SLOT(batchEnergy()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(false);
  action->setText(tr("Forces (All Conformers)"));
  action->setData(batchForcesAction);
  action->setProperty("menu priority", 905);
  connect(action, SIGNAL(triggered()), SLOT(batchForces()));
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

  const QList<QThread*> stillRunning = m_retiredThreads;
  for (QThread* thread : stillRunning) {
    thread->quit();
    thread->wait();
  }
  m_retiredThreads.clear();
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

void Forcefield::registerCommands()
{
  emit registerCommand(
    "listForceFields",
    tr("List the force fields available for the current molecule."));
  emit registerCommand(
    "energy", tr("Compute the force field energy of the current molecule."));
  emit registerCommand(
    "forces", tr("Compute the force field forces on the current molecule."));
  emit registerCommand("optimize",
                       tr("Optimize the geometry of the current molecule."));
  emit registerCommand(
    "freezeSelected",
    tr("Freeze selected atoms during force field optimization."));
  emit registerCommand("unfreezeSelected", tr("Unfreeze selected atoms."));
  emit registerCommand(
    "freezeAxis", tr("Freeze a specific axis (X, Y, or Z) of selected atoms."));
}

bool Forcefield::handleCommand(const QString& command,
                               const QVariantMap& options)
{
  if (command == "listForceFields") {
    handleListForceFieldsCommand();
    return true;
  }
  if (command == "energy") {
    handleEnergyCommand(options);
    return true;
  }
  if (command == "forces") {
    handleForcesCommand(options);
    return true;
  }
  if (command == "optimize") {
    handleOptimizeCommand(options);
    return true;
  }
  if (command == "freezeSelected") {
    handleFreezeSelectedCommand();
    return true;
  }
  if (command == "unfreezeSelected") {
    handleUnfreezeSelectedCommand();
    return true;
  }
  if (command == "freezeAxis") {
    handleFreezeAxisCommand(options);
    return true;
  }

  return false;
}

QString Forcefield::convergenceReasonName(ConvergenceReason reason)
{
  switch (reason) {
    case ConvergenceReason::Gradient:
      return QStringLiteral("gradient");
    case ConvergenceReason::Energy:
      return QStringLiteral("energy");
    case ConvergenceReason::OptimizerStopped:
      return QStringLiteral("optimizerStopped");
    case ConvergenceReason::MaxSteps:
      return QStringLiteral("maxSteps");
    case ConvergenceReason::NonFinite:
      return QStringLiteral("nonFinite");
    default:
      return QString();
  }
}

void Forcefield::handleListForceFieldsCommand()
{
  emit commandStarted();

  QStringList names;
  QVariantList methods;
  QString recommended;
  QString current;

  if (m_molecule != nullptr) {
    auto compatible =
      Calc::EnergyManager::instance().identifiersForMolecule(*m_molecule);
    for (const auto& id : compatible) {
      const QString idString = QString::fromStdString(id);
      names << idString;
      QVariantMap entry;
      entry["id"] = idString;
      entry["name"] = QString::fromStdString(
        Calc::EnergyManager::instance().nameForModel(id));
      methods.push_back(entry);
    }

    // The same ranking autodetect uses in setupMethod().
    recommended = QString::fromStdString(
      Calc::EnergyManager::instance().recommendedModel(*m_molecule));

    if (m_method == nullptr)
      setupMethod();
    current = QString::fromStdString(m_methodName);
  }

  QVariantMap result;
  result["names"] = names;
  result["count"] = names.size();
  result["methods"] = methods;
  result["recommended"] = recommended;
  result["current"] = current;

  emit commandFinished(tr("%1 force field(s) available.").arg(names.size()),
                       result);
}

void Forcefield::handleEnergyCommand(const QVariantMap& options)
{
  if (m_molecule == nullptr) {
    emit commandFailed(tr("No molecule is open."));
    return;
  }
  if (m_worker != nullptr || m_optimizing) {
    emit commandFailed(tr("A force field calculation is already running."));
    return;
  }
  if (m_molecule->atomCount() == 0) {
    emit commandFailed(tr("No atoms provided for energy calculation."));
    return;
  }

  QString error;
  std::string methodId;
  if (!resolveMethod(options.value("method").toString(), methodId, error)) {
    emit commandFailed(error);
    return;
  }

  emit commandStarted();
  startEnergyCalculation(methodId, PendingCommand::Energy);
}

void Forcefield::handleForcesCommand(const QVariantMap& options)
{
  if (m_molecule == nullptr) {
    emit commandFailed(tr("No molecule is open."));
    return;
  }
  if (m_worker != nullptr || m_optimizing) {
    emit commandFailed(tr("A force field calculation is already running."));
    return;
  }
  if (m_molecule->atomCount() == 0) {
    emit commandFailed(tr("No atoms provided for force calculation."));
    return;
  }

  QString error;
  std::string methodId;
  if (!resolveMethod(options.value("method").toString(), methodId, error)) {
    emit commandFailed(error);
    return;
  }

  emit commandStarted();
  startForcesCalculation(methodId, PendingCommand::Forces);
}

void Forcefield::handleOptimizeCommand(const QVariantMap& options)
{
  if (m_molecule == nullptr) {
    emit commandFailed(tr("No molecule is open."));
    return;
  }
  if (m_worker != nullptr || m_optimizing) {
    emit commandFailed(tr("A force field calculation is already running."));
    return;
  }
  if (m_molecule->atomCount() == 0) {
    emit commandFailed(tr("No atoms provided for optimization."));
    return;
  }

  QString error;
  std::string methodId;
  if (!resolveMethod(options.value("method").toString(), methodId, error)) {
    emit commandFailed(error);
    return;
  }

  OptimizeRunOptions runOptions;
  runOptions.maxSteps = m_maxSteps;
  runOptions.gradientTolerance = m_gradientTolerance;
  runOptions.tolerance = m_tolerance;

  if (options.contains("steps")) {
    bool ok = false;
    const int steps = options.value("steps").toInt(&ok);
    if (!ok || steps < 1) {
      emit commandFailed(tr("\"steps\" must be a positive integer."));
      return;
    }
    runOptions.maxSteps = static_cast<unsigned int>(steps);
  }
  if (options.contains("gradientTolerance")) {
    bool ok = false;
    const double tolerance = options.value("gradientTolerance").toDouble(&ok);
    if (!ok || !std::isfinite(tolerance) || tolerance < 0.0) {
      emit commandFailed(
        tr("\"gradientTolerance\" must be a finite, non-negative number."));
      return;
    }
    runOptions.gradientTolerance = tolerance;
  }
  if (options.contains("energyTolerance")) {
    bool ok = false;
    const double tolerance = options.value("energyTolerance").toDouble(&ok);
    if (!ok || !std::isfinite(tolerance) || tolerance < 0.0) {
      emit commandFailed(
        tr("\"energyTolerance\" must be a finite, non-negative number."));
      return;
    }
    runOptions.tolerance = tolerance;
  }

  emit commandStarted();
  startOptimizeCalculation(methodId, runOptions, PendingCommand::Optimize);
}

void Forcefield::handleFreezeSelectedCommand()
{
  if (m_molecule == nullptr) {
    emit commandFailed(tr("No molecule is open."));
    return;
  }
  if (m_molecule->isSelectionEmpty()) {
    emit commandFailed(tr("No atoms are selected."));
    return;
  }

  int count = 0;
  auto numAtoms = m_molecule->atomCount();
  for (Index i = 0; i < numAtoms; ++i) {
    if (m_molecule->atomSelected(i))
      ++count;
  }

  freezeSelected();

  QVariantMap result;
  result["count"] = count;
  emit commandFinished(tr("Froze %n atom(s).", "", count), result);
}

void Forcefield::handleUnfreezeSelectedCommand()
{
  if (m_molecule == nullptr) {
    emit commandFailed(tr("No molecule is open."));
    return;
  }
  if (m_molecule->isSelectionEmpty()) {
    emit commandFailed(tr("No atoms are selected."));
    return;
  }

  int count = 0;
  auto numAtoms = m_molecule->atomCount();
  for (Index i = 0; i < numAtoms; ++i) {
    if (m_molecule->atomSelected(i))
      ++count;
  }

  unfreezeSelected();

  QVariantMap result;
  result["count"] = count;
  emit commandFinished(tr("Unfroze %n atom(s).", "", count), result);
}

void Forcefield::handleFreezeAxisCommand(const QVariantMap& options)
{
  if (m_molecule == nullptr) {
    emit commandFailed(tr("No molecule is open."));
    return;
  }
  if (m_molecule->isSelectionEmpty()) {
    emit commandFailed(tr("No atoms are selected."));
    return;
  }
  if (!options.contains("axis")) {
    emit commandFailed(tr("No axis was given."));
    return;
  }

  QVariant axisData = options.value("axis");
  int axisId = -1; // Default to invalid

  // If the user sent a string like "x" or "Y"
  if (axisData.typeId() == QMetaType::QString) {
    QString axisStr = axisData.toString().toLower();
    if (axisStr == "x")
      axisId = 0;
    else if (axisStr == "y")
      axisId = 1;
    else if (axisStr == "z")
      axisId = 2;
  }
  // If the user sent an integer like 0, 1, or 2
  else {
    bool ok = false;
    axisId = axisData.toInt(&ok);
    if (!ok) {
      axisId = -1;
    }
  }

  if (axisId < 0 || axisId > 2) {
    emit commandFailed(tr("Axis must be x, y, z or 0, 1, 2."));
    return;
  }

  int count = 0;
  auto numAtoms = m_molecule->atomCount();
  for (Index i = 0; i < numAtoms; ++i) {
    if (m_molecule->atomSelected(i))
      ++count;
  }

  freezeAxis(axisId);

  QVariantMap result;
  result["count"] = count;
  result["axis"] = axisId;
  emit commandFinished(tr("Froze %n atom(s).", "", count), result);
}

void Forcefield::showDialog()
{
  if (m_molecule == nullptr)
    return;

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

  // m_molecule is guaranteed non-null here (see the guard above).
  const std::string recommended =
    Calc::EnergyManager::instance().recommendedModel(*m_molecule);
  QVariantMap results = ForceFieldDialog::prompt(nullptr, forceFields, options,
                                                 recommended.c_str());

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

  // Any running calculation belongs to the outgoing molecule. Cancel it and
  // close its undo merge before switching, so queued results can't be applied
  // to the new molecule (cleanupWorker() disconnects the worker, so the
  // sender() checks in the result handlers reject anything still in flight).
  if (m_worker != nullptr || m_optimizing || m_batchRunning) {
    if (m_optimizing && m_molecule != nullptr)
      m_molecule->undoMolecule()->setInteractive(false);
    cleanupWorker();
  }

  // Disconnect from the old molecule so it no longer drives our actions.
  if (m_molecule != nullptr)
    disconnect(m_molecule, SIGNAL(changed(unsigned int)), this,
               SLOT(updateActions()));

  m_molecule = mol;

  // Refresh action enable-state (e.g. batch actions) when the molecule
  // changes - conformers may be added or removed.
  connect(m_molecule, SIGNAL(changed(unsigned int)), SLOT(updateActions()));
  updateActions();
}

void Forcefield::updateActions()
{
  if (m_molecule == nullptr)
    return;

  bool noSelection = m_molecule->isSelectionEmpty();
  bool hasConformers = m_molecule->coordinate3dCount() > 1;
  foreach (QAction* action, m_actions) {
    switch (action->data().toInt()) {
      case freezeAction:
      case unfreezeAction:
      case fuseAction:
      case unfuseAction:
        action->setEnabled(!noSelection);
        break;
      case batchEnergyAction:
      case batchForcesAction:
        action->setEnabled(hasConformers);
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
    m_methodName =
      Calc::EnergyManager::instance().recommendedModel(*m_molecule);

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
    m_methodName =
      Calc::EnergyManager::instance().recommendedModel(*m_molecule);
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
  delete m_pendingCalc;
  m_pendingCalc = nullptr;

  if (m_workerThread) {
    if (m_worker) {
      m_worker->cancel();
      // A queued result can be delivered after a timeout. Disconnect it so
      // an obsolete operation cannot update or tear down a newer worker.
      disconnect(m_worker, nullptr, this, nullptr);
    }
    m_workerThread->quit();
    if (m_workerThread->wait(5000)) {
      m_workerThread->deleteLater();
    } else {
      QThread* stalled = m_workerThread;
      m_retiredThreads.append(stalled);
      connect(stalled, &QThread::finished, this, [this, stalled]() {
        m_retiredThreads.removeAll(stalled);
        stalled->deleteLater();
      });
    }
    m_workerThread = nullptr;
    m_worker = nullptr;
  }
  if (m_progressDialog) {
    m_progressDialog->hide();
    m_progressDialog->deleteLater();
    m_progressDialog = nullptr;
  }
  m_optimizing = false;
  m_batchRunning = false;

  // A command left pending when the worker it was waiting on gets torn down
  // (e.g. setMolecule() switching molecules mid-run, or the position-count
  // sanity check in onOptimizeChunkDone()) would otherwise leave the caller
  // waiting for the full RPC timeout. Every other path that finishes a
  // command clears m_pendingCommand before calling cleanupWorker(), so
  // reaching this with it still set means the run did not finish on its own.
  if (m_pendingCommand != PendingCommand::None) {
    m_pendingCommand = PendingCommand::None;
    emit commandFailed(tr("The force field calculation was interrupted."));
  }
}

void Forcefield::startWorker(const std::string& methodId)
{
  cleanupWorker();

  auto n = m_molecule->atomCount();

  // Build the frozen atom mask
  auto mask = m_molecule->frozenAtomMask();
  if (mask.rows() != static_cast<Eigen::Index>(3 * n))
    mask = Eigen::VectorXd::Ones(static_cast<Eigen::Index>(3 * n));

  auto constraints = m_molecule->constraints();

  // Create a fresh calculator clone for the worker thread
  auto* calc = Calc::EnergyManager::instance().model(methodId);
  if (calc == nullptr)
    return;

  // Apply user options to the clone
  const QString methodIdString = QString::fromStdString(methodId);
  const QString modelOptions =
    m_modelUserOptions.value(methodIdString).toString();
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

bool Forcefield::resolveMethod(const QString& methodOption,
                               std::string& methodId, QString& errorMessage)
{
  if (methodOption.isEmpty()) {
    // No method requested: use exactly what the GUI would.
    if (m_method == nullptr)
      setupMethod();
    if (m_method == nullptr) {
      errorMessage = tr("No force field is available for this molecule.");
      return false;
    }
    methodId = m_methodName;
    return true;
  }

  // An explicit request must be compatible with this molecule -- no falling
  // back to the recommended method, which would silently report a different
  // force field's numbers under the name the caller asked for.
  const std::string requested = methodOption.toStdString();
  auto compatible =
    Calc::EnergyManager::instance().identifiersForMolecule(*m_molecule);
  if (compatible.find(requested) != compatible.end()) {
    methodId = requested;
    return true;
  }

  auto all = Calc::EnergyManager::instance().identifiers();
  if (all.find(requested) != all.end()) {
    errorMessage =
      tr("Force field \"%1\" is not compatible with this molecule.")
        .arg(methodOption);
  } else {
    errorMessage = tr("Unknown force field \"%1\".").arg(methodOption);
  }
  return false;
}

void Forcefield::optimize()
{
  if (m_molecule == nullptr || m_optimizing || m_worker != nullptr)
    return;

  QString error;
  std::string methodId;
  if (!resolveMethod(QString(), methodId, error))
    return;

  if (!m_molecule->atomCount()) {
    QMessageBox::information(nullptr, tr("Avogadro"),
                             tr("No atoms provided for optimization"));
    return;
  }

  OptimizeRunOptions runOptions;
  runOptions.maxSteps = m_maxSteps;
  runOptions.gradientTolerance = m_gradientTolerance;
  runOptions.tolerance = m_tolerance;

  startOptimizeCalculation(methodId, runOptions, PendingCommand::None);
}

void Forcefield::startOptimizeCalculation(const std::string& methodId,
                                          const OptimizeRunOptions& runOptions,
                                          PendingCommand pending)
{
  m_runOptions = runOptions;
  m_iterationsDone = 0;

  // merge all coordinate updates into one undo step
  m_molecule->undoMolecule()->setInteractive(true);

  // Set up optimization options. Hybrid drives ABC-FIRE until |g|_inf
  // drops below ~5 kJ/(mol*A), then hands off to L-BFGS for the tail.
  // Start with a small chunk so the first frame lands quickly; the size
  // adapts per chunk in onOptimizeChunkDone to target ~30 fps.
  m_optOptions.algorithm = Calc::OptimizationAlgorithm::Hybrid;
  m_optOptions.chunkIterations = 5;

  // Snapshot current positions
  auto n = m_molecule->atomCount();
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  Eigen::Map<Eigen::VectorXd> map(pos[0].data(), 3 * n);
  m_lastPositions = map;
  m_lastEnergy = 0.0;
  m_hasPreviousEnergy = false;

  // Start the worker first (calls cleanupWorker() which resets m_optimizing)
  startWorker(methodId);

  if (!m_worker) {
    m_molecule->undoMolecule()->setInteractive(false);
    if (pending != PendingCommand::None)
      emit commandFailed(tr("Could not create a calculator for \"%1\".")
                           .arg(QString::fromStdString(methodId)));
    return;
  }

  // Set m_optimizing AFTER startWorker, since cleanupWorker resets it
  m_optimizing = true;
  m_pendingCommand = pending;
  m_activeMethodName = methodId;

  if (pending == PendingCommand::None) {
    // Progress dialog and cancel button are GUI-only; a command run has no
    // window to show one in, and no cancel button to click.
    m_progressDialog =
      new QProgressDialog(qobject_cast<QWidget*>(this->parent()));
    m_progressDialog->setWindowTitle(tr("Optimize Geometry"));
    // cancel button text is set automatically
    m_progressDialog->setRange(0, static_cast<int>(m_runOptions.maxSteps));
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
  }

  connect(m_worker, &QtGui::CalcWorker::calculatorReady, this,
          &Forcefield::onWorkerReady);
  connect(m_worker, &QtGui::CalcWorker::optimizeFinished, this,
          &Forcefield::onOptimizeChunkDone);

  sendInitCalculator();
}

void Forcefield::onWorkerReady()
{
  if (sender() != m_worker || !m_optimizing || !m_worker)
    return;

  // Send the first optimization chunk. Time round-trip (dispatch + work +
  // signal back) so adaptive chunk sizing reflects the actual UI cadence.
  m_chunkTimer.start();
  QMetaObject::invokeMethod(
    m_worker, "runOptimizeChunk", Qt::QueuedConnection,
    Q_ARG(Eigen::VectorXd, m_lastPositions),
    Q_ARG(Avogadro::Calc::OptimizationOptions, m_optOptions));
}

void Forcefield::onOptimizeChunkDone(Eigen::VectorXd positions,
                                     Eigen::VectorXd gradient, double energy,
                                     bool converged)
{
  if (sender() != m_worker || !m_optimizing || m_molecule == nullptr)
    return;

  // Measure chunk wall time (round-trip) before launching the next chunk.
  // nsecsElapsed gives us sub-ms resolution so adaptation still works when
  // small molecules finish a chunk in well under 1 ms.
  const double elapsedMs =
    m_chunkTimer.isValid() ? m_chunkTimer.nsecsElapsed() / 1.0e6 : 0.0;

  auto n = m_molecule->atomCount();
  if (n == 0 || positions.size() != 3 * static_cast<Eigen::Index>(n)) {
    m_molecule->undoMolecule()->setInteractive(false);
    cleanupWorker();
    return;
  }
  const unsigned int chunkRan = m_optOptions.chunkIterations;
  m_iterationsDone += chunkRan;

  if (m_progressDialog) {
    m_progressDialog->setValue(static_cast<int>(m_iterationsDone));
    m_progressDialog->setLabelText(
      tr("Energy: %L1", "force field energy").arg(energy, 0, 'f', 3));
  }

#ifndef NDEBUG
  qDebug() << " optimize " << m_iterationsDone << energy
           << " gradNorm: " << gradient.norm() << " chunk=" << chunkRan
           << " ms=" << elapsedMs;
#endif

  // CalcWorker sets its "converged" flag with an empty gradient (and a
  // placeholder energy of 0.0) when it could not run this chunk at all --
  // no calculator, or the run was cancelled (see
  // CalcWorker::runOptimizeChunk). That is not a discovered minimum:
  // Calc::optimizeSteps only returns false for a malformed chunk size or an
  // unrecognized algorithm, and the two real optimizers (L-BFGS, FIRE)
  // always return true. Detect that case so a placeholder energy/gradient
  // never gets written into the molecule as if it were a real result.
  const bool noResult =
    converged && gradient.size() != 3 * static_cast<Eigen::Index>(n);

  // Update coordinates if valid
  bool nonFinite = false;
  if (!noResult && std::isfinite(energy) && positions.allFinite()) {
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
  } else if (!noResult) {
    qDebug() << "Non-finite energy, stopping optimization" << energy;
    nonFinite = true;
  }

  // Check convergence criteria, tracking which one ended the run so the
  // "optimize" command can report why (more useful to a script than the
  // bare bool).
  bool done = false;
  ConvergenceReason reason = ConvergenceReason::None;

  if (nonFinite) {
    done = true;
    reason = ConvergenceReason::NonFinite;
  } else if (converged) {
    // The worker could not run this chunk at all (see the comment above) --
    // never a discovered minimum, so this is never reported as converged.
    done = true;
    reason = ConvergenceReason::OptimizerStopped;
  }

  if (!done && gradient.size() > 0) {
    // largest component magnitude, |g|_inf -- same test as energyoptimizer
    if (gradient.cwiseAbs().maxCoeff() < m_runOptions.gradientTolerance) {
      done = true;
      reason = ConvergenceReason::Gradient;
    } else if (m_hasPreviousEnergy && chunkRan > 0 &&
               // Compare the per-iteration energy change within this chunk,
               // not the raw chunk-to-chunk change: chunk size adapts from 1
               // to 200 iterations to hold ~30 fps, so comparing whole chunks
               // made the stopping point depend on how fast the machine
               // renders. m_hasPreviousEnergy (rather than testing
               // m_lastEnergy != 0.0) also stops skipping the test for a
               // molecule whose energy happens to be exactly zero.
               fabs(energy - m_lastEnergy) / chunkRan <
                 m_runOptions.tolerance) {
      done = true;
      reason = ConvergenceReason::Energy;
    }
  }

  if (!done && m_iterationsDone >= m_runOptions.maxSteps) {
    done = true;
    reason = ConvergenceReason::MaxSteps;
  }

  m_lastEnergy = energy;
  m_hasPreviousEnergy = true;

  const bool canceled = m_progressDialog && m_progressDialog->wasCanceled();

  if (done || canceled) {
    // Optimization complete
    m_molecule->undoMolecule()->setInteractive(false);

    // Capture what the completed run was for before cleanupWorker() clears
    // m_worker -- clear m_pendingCommand first so cleanupWorker()'s own
    // "command left pending" check does not fire for this (successful) run.
    const PendingCommand pending = m_pendingCommand;
    const std::string methodId = m_activeMethodName;
    const unsigned int iterationsDone = m_iterationsDone;
    m_pendingCommand = PendingCommand::None;
    cleanupWorker();

    if (pending == PendingCommand::Optimize) {
      if (noResult) {
        // energy/gradient are placeholders (0.0 / empty), not a real result
        // -- report failure rather than a finished run at a fabricated
        // zero energy.
        emit commandFailed(
          tr("The optimizer stopped without producing a result."));
      } else {
        // "maxSteps", "nonFinite" and "optimizerStopped" are not
        // convergence: the run stopped because it ran out of budget, the
        // model broke down, or the optimizer itself could not continue --
        // not because it found a minimum.
        const bool didConverge = reason == ConvergenceReason::Gradient ||
                                 reason == ConvergenceReason::Energy;

        QVariantMap result;
        result["energy"] = energy;
        result["unit"] = QStringLiteral("kJ/mol");
        result["method"] = QString::fromStdString(methodId);
        result["steps"] = static_cast<int>(iterationsDone);
        result["converged"] = didConverge;
        result["reason"] = convergenceReasonName(reason);
        emit commandFinished(
          tr("%1 Energy = %L2").arg(methodId.c_str()).arg(energy), result);
      }
    }
  } else {
    // Adapt chunk size toward ~30 fps using the measured round-trip. Cap
    // at the remaining iteration budget so we don't overshoot m_maxSteps.
    constexpr double kTargetMs = 33.0; // 30 fps
    constexpr double kSmoothing = 0.7; // ~2-chunk convergence to target
    constexpr size_t kMinChunk = 1;
    constexpr size_t kMaxChunk = 200;
    size_t next = Calc::adaptChunkIterations(chunkRan, elapsedMs, kTargetMs,
                                             kSmoothing, kMinChunk, kMaxChunk);
    const unsigned int remaining = m_runOptions.maxSteps - m_iterationsDone;
    if (next > remaining)
      next = remaining;
    m_optOptions.chunkIterations = next;

    // Request next chunk
    m_chunkTimer.start();
    QMetaObject::invokeMethod(
      m_worker, "runOptimizeChunk", Qt::QueuedConnection,
      Q_ARG(Eigen::VectorXd, m_lastPositions),
      Q_ARG(Avogadro::Calc::OptimizationOptions, m_optOptions));
  }
}

void Forcefield::energy()
{
  if (m_molecule == nullptr || m_optimizing || m_worker != nullptr)
    return;

  QString error;
  std::string methodId;
  if (!resolveMethod(QString(), methodId, error))
    return;

  if (m_molecule->atomCount() == 0) {
    QMessageBox::information(nullptr, tr("Avogadro"),
                             tr("No atoms provided for energy calculation"));
    return;
  }

  startEnergyCalculation(methodId, PendingCommand::None);
}

void Forcefield::startEnergyCalculation(const std::string& methodId,
                                        PendingCommand pending)
{
  auto n = m_molecule->atomCount();
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  Eigen::Map<Eigen::VectorXd> map(pos[0].data(), 3 * n);
  Eigen::VectorXd positions = map;

  startWorker(methodId);

  if (!m_worker) {
    if (pending != PendingCommand::None)
      emit commandFailed(tr("Could not create a calculator for \"%1\".")
                           .arg(QString::fromStdString(methodId)));
    return;
  }

  m_pendingCommand = pending;
  m_activeMethodName = methodId;

  auto* worker = m_worker;

  connect(worker, &QtGui::CalcWorker::calculatorReady, this,
          [this, worker, positions]() {
            if (worker != m_worker)
              return;
            QMetaObject::invokeMethod(
              worker, "runEvaluate", Qt::QueuedConnection,
              Q_ARG(Eigen::VectorXd, positions), Q_ARG(bool, false));
          });
  connect(worker, &QtGui::CalcWorker::evaluateFinished, this,
          &Forcefield::onEnergyDone);

  sendInitCalculator();
}

void Forcefield::onEnergyDone(Eigen::VectorXd gradient, double energy)
{
  Q_UNUSED(gradient);
  if (sender() != m_worker)
    return;

  // Capture what the completed run was for before cleanupWorker() clears
  // m_worker -- clear m_pendingCommand first so cleanupWorker()'s own
  // "command left pending" check does not fire for this (successful) run.
  const PendingCommand pending = m_pendingCommand;
  const std::string methodId = m_activeMethodName;
  m_pendingCommand = PendingCommand::None;
  cleanupWorker();

  QString msg(tr("%1 Energy = %L2").arg(methodId.c_str()).arg(energy));

  if (pending == PendingCommand::Energy) {
    if (!std::isfinite(energy)) {
      emit commandFailed(tr("%1 returned a non-finite energy.")
                           .arg(QString::fromStdString(methodId)));
      return;
    }
    QVariantMap result;
    result["energy"] = energy;
    result["unit"] = QStringLiteral("kJ/mol");
    result["method"] = QString::fromStdString(methodId);
    emit commandFinished(msg, result);
    return;
  }

  QMessageBox::information(nullptr, tr("Avogadro"), msg);
}

void Forcefield::forces()
{
  if (m_molecule == nullptr || m_optimizing || m_worker != nullptr)
    return;

  QString error;
  std::string methodId;
  if (!resolveMethod(QString(), methodId, error))
    return;

  if (m_molecule->atomCount() == 0) {
    QMessageBox::information(nullptr, tr("Avogadro"),
                             tr("No atoms provided for force calculation"));
    return;
  }

  startForcesCalculation(methodId, PendingCommand::None);
}

void Forcefield::startForcesCalculation(const std::string& methodId,
                                        PendingCommand pending)
{
  auto n = m_molecule->atomCount();
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  Eigen::Map<Eigen::VectorXd> map(pos[0].data(), 3 * n);
  Eigen::VectorXd positions = map;

  startWorker(methodId);

  if (!m_worker) {
    if (pending != PendingCommand::None)
      emit commandFailed(tr("Could not create a calculator for \"%1\".")
                           .arg(QString::fromStdString(methodId)));
    return;
  }

  m_pendingCommand = pending;
  m_activeMethodName = methodId;

  auto* worker = m_worker;

  connect(worker, &QtGui::CalcWorker::calculatorReady, this,
          [this, worker, positions]() {
            if (worker != m_worker)
              return;
            QMetaObject::invokeMethod(worker, "runGradient",
                                      Qt::QueuedConnection,
                                      Q_ARG(Eigen::VectorXd, positions));
          });
  connect(worker, &QtGui::CalcWorker::evaluateFinished, this,
          &Forcefield::onForcesDone);

  sendInitCalculator();
}

void Forcefield::onForcesDone(Eigen::VectorXd gradient, double energy)
{
  if (sender() != m_worker)
    return;

  const PendingCommand pending = m_pendingCommand;
  const std::string methodId = m_activeMethodName;

  if (m_molecule == nullptr) {
    m_pendingCommand = PendingCommand::None;
    cleanupWorker();
    if (pending == PendingCommand::Forces)
      emit commandFailed(tr("The molecule changed during the calculation."));
    return;
  }

  auto n = m_molecule->atomCount();

  // Reject an unusable result before it reaches the displayed force vectors
  // or the caller.
  if (pending == PendingCommand::Forces &&
      (!std::isfinite(energy) || !gradient.allFinite() ||
       gradient.size() != 3 * static_cast<Eigen::Index>(n))) {
    m_pendingCommand = PendingCommand::None;
    cleanupWorker();
    emit commandFailed(tr("%1 returned a non-finite or incomplete result.")
                         .arg(QString::fromStdString(methodId)));
    return;
  }

  Core::Array<Vector3> forces(n);
  if (n > 0 && gradient.size() == 3 * static_cast<Eigen::Index>(n))
    Eigen::Map<Eigen::VectorXd>(forces[0].data(), 3 * n) = -gradient;

  // Like the menu action, always update the displayed force vectors -- for
  // a command as well as the GUI, since the point is to show what was
  // computed.
  m_molecule->setForceVectors(forces);
  Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Modified;
  m_molecule->emitChanged(changes);

  // Clear m_pendingCommand before cleanupWorker() so its own "command left
  // pending" check does not fire for this (successful) run.
  m_pendingCommand = PendingCommand::None;
  cleanupWorker();

  QString msg(
    tr("%1 Force Norm = %L2").arg(methodId.c_str()).arg(gradient.norm()));

  if (pending == PendingCommand::Forces) {
    // cleanGradients() zeroes the components of frozen atoms/axes, and also
    // silently zeroes any non-finite component -- so a zero force here means
    // "frozen, or balanced, or the model produced a NaN", not necessarily
    // "at a minimum".
    QVariantList forceList;
    double maxForce = 0.0;
    for (Index i = 0; i < n; ++i) {
      const Vector3& f = forces[i];
      forceList.push_back(QVariantList{ f.x(), f.y(), f.z() });
      maxForce = std::max(maxForce, f.norm());
    }
    const double rmsForce =
      gradient.size() > 0
        ? gradient.norm() / std::sqrt(static_cast<double>(gradient.size()))
        : 0.0;

    QVariantMap result;
    result["forces"] = forceList;
    result["energy"] = energy;
    result["rmsForce"] = rmsForce;
    result["maxForce"] = maxForce;
    result["unit"] = QStringLiteral("kJ/(mol*Angstrom)");
    result["method"] = QString::fromStdString(methodId);
    emit commandFinished(msg, result);
    return;
  }

  QMessageBox::information(nullptr, tr("Avogadro"), msg);
}

std::vector<Eigen::VectorXd> Forcefield::gatherCoordinateSets() const
{
  std::vector<Eigen::VectorXd> coords;
  if (m_molecule == nullptr)
    return coords;

  const auto count = m_molecule->coordinate3dCount();
  const auto n = m_molecule->atomCount();
  coords.reserve(count);
  for (size_t c = 0; c < count; ++c) {
    // coordinate3d() returns a copy and does not change the displayed set.
    Core::Array<Vector3> set = m_molecule->coordinate3d(c);
    // Zero first - a short coordinate set would otherwise leave the tail
    // uninitialized and send garbage to the calculator.
    Eigen::VectorXd x = Eigen::VectorXd::Zero(3 * n);
    for (size_t i = 0; i < n && i < set.size(); ++i) {
      x[3 * i] = set[i].x();
      x[3 * i + 1] = set[i].y();
      x[3 * i + 2] = set[i].z();
    }
    coords.push_back(x);
  }
  return coords;
}

void Forcefield::batchEnergy()
{
  runBatch(false);
}

void Forcefield::batchForces()
{
  runBatch(true);
}

void Forcefield::runBatch(bool computeGradient)
{
  if (m_molecule == nullptr || m_optimizing || m_batchRunning)
    return;

  if (m_method == nullptr)
    setupMethod();
  if (m_method == nullptr)
    return;

  if (m_molecule->coordinate3dCount() < 2) {
    QMessageBox::information(nullptr, tr("Avogadro"),
                             tr("This molecule has only one coordinate set."));
    return;
  }

  std::vector<Eigen::VectorXd> coords = gatherCoordinateSets();
  if (coords.empty())
    return;

  m_batchGradient = computeGradient;

  startWorker(m_methodName);

  if (!m_worker)
    return;

  m_batchRunning = true;

  auto* worker = m_worker;

  const int total = static_cast<int>(coords.size());
  m_progressDialog =
    new QProgressDialog(qobject_cast<QWidget*>(this->parent()));
  m_progressDialog->setWindowTitle(computeGradient
                                     ? tr("Forces (All Conformers)")
                                     : tr("Energies (All Conformers)"));
  m_progressDialog->setRange(0, total);
  m_progressDialog->setWindowModality(Qt::WindowModal);
  m_progressDialog->setMinimumDuration(0);
  m_progressDialog->show();

  connect(m_progressDialog, &QProgressDialog::canceled, this, [this]() {
    if (m_worker)
      m_worker->cancel();
    cleanupWorker();
    m_batchRunning = false;
  });

  connect(worker, &QtGui::CalcWorker::batchProgress, this,
          [this, worker](int done, int totalSets) {
            if (worker != m_worker)
              return;
            if (m_progressDialog) {
              m_progressDialog->setRange(0, totalSets);
              m_progressDialog->setValue(done);
            }
          });

  connect(worker, &QtGui::CalcWorker::calculatorReady, this,
          [this, worker, coords, computeGradient]() {
            if (worker != m_worker)
              return;
            QMetaObject::invokeMethod(
              worker, "runEvaluateBatch", Qt::QueuedConnection,
              Q_ARG(std::vector<Eigen::VectorXd>, coords),
              Q_ARG(bool, computeGradient), Q_ARG(int, 0));
          });
  connect(worker, &QtGui::CalcWorker::evaluateBatchFinished, this,
          &Forcefield::onBatchDone);

  sendInitCalculator();
}

void Forcefield::onBatchDone(std::vector<double> energies,
                             std::vector<Eigen::VectorXd> gradients)
{
  if (sender() != m_worker)
    return;

  m_batchRunning = false;

  if (m_molecule == nullptr) {
    cleanupWorker();
    return;
  }

  const auto n = m_molecule->atomCount();
  const auto coordCount = m_molecule->coordinate3dCount();

  // A cancelled batch finishes with only the chunks completed so far. Storing
  // those would leave "energies"/"forces" out of step with the coordinate
  // sets, so only persist a result that covers every conformer.
  const bool energiesComplete = (energies.size() == coordCount);
  const bool gradientsComplete = (gradients.size() == coordCount);

  // Store one energy per coordinate set (read by the conformer plot).
  if (energiesComplete) {
    m_molecule->setData("energies", Core::Variant(energies));
    // These replace whatever the file supplied, so the recorded unit has to
    // be replaced along with them -- energies read from ORCA are Hartree, and
    // leaving that behind would show these 627 times too large. Every energy
    // model reaching here reports kJ/mol: UFF and the Open Babel methods
    // convert to it, and the scripted models are held to it by the plugin
    // contract.
    Core::setEnergyUnit(*m_molecule, "kJ/mol");
  }

  // Store forces two ways:
  //   * data("forces") - the RMS gradient (|g| / sqrt(3N)) per coordinate
  //     set, the scalar convention shared with the readers and read by the
  //     conformer plot (parallels data("energies")).
  //   * conformerProperties("forces") - the full (N x 3) force matrix per
  //     coordinate set, for richer per-atom use.
  if (gradientsComplete) {
    std::vector<double> rmsGradients;
    rmsGradients.reserve(gradients.size());
    for (size_t c = 0; c < gradients.size(); ++c) {
      const Eigen::VectorXd& g = gradients[c];
      rmsGradients.push_back(
        g.size() > 0 ? g.norm() / std::sqrt(static_cast<double>(g.size()))
                     : 0.0);

      MatrixX forceMat(static_cast<Eigen::Index>(n), 3);
      forceMat.setZero();
      for (size_t i = 0; i < n && 3 * i + 2 < static_cast<size_t>(g.size());
           ++i) {
        forceMat(static_cast<Eigen::Index>(i), 0) = -g[3 * i];
        forceMat(static_cast<Eigen::Index>(i), 1) = -g[3 * i + 1];
        forceMat(static_cast<Eigen::Index>(i), 2) = -g[3 * i + 2];
      }
      m_molecule->conformerProperties().setMatrix(
        "forces", static_cast<Index>(c), forceMat);
    }
    m_molecule->setData("forces", Core::Variant(rmsGradients));
  }

  // Update the displayed force vectors for the currently shown conformer. This
  // is ephemeral display state, so it is worth showing even for a partial run,
  // as long as the active conformer itself was evaluated.
  const size_t activeIndex = static_cast<size_t>(m_molecule->coordinate3d());
  if (activeIndex < gradients.size() &&
      static_cast<size_t>(gradients[activeIndex].size()) >= 3 * n) {
    Core::Array<Vector3> forceVecs(n, Vector3::Zero());
    const Eigen::VectorXd& g = gradients[activeIndex];
    for (size_t i = 0; i < n; ++i)
      forceVecs[i] = Vector3(-g[3 * i], -g[3 * i + 1], -g[3 * i + 2]);
    m_molecule->setForceVectors(forceVecs);
  }

  Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Modified;
  m_molecule->emitChanged(changes);

  cleanupWorker();
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
