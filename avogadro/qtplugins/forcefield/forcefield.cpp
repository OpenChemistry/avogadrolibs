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
#include <QtCore/QSettings>
#include <QtCore/QTimer>

#include <QAction>
#include <QtWidgets/QMessageBox>

#include <QMutex>
#include <QMutexLocker>
#include <QProgressDialog>
#include <QWriteLocker>

#include <avogadro/qtgui/avogadropython.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/qtgui/utilities.h>

#include <avogadro/qtgui/scriptloader.h>

#include <avogadro/calc/energymanager.h>
#include <avogadro/calc/lennardjones.h>

#include <cppoptlib/meta.h>
#include <cppoptlib/problem.h>
#include <cppoptlib/solver/lbfgssolver.h>

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
  connect(action, SIGNAL(triggered()), SLOT(freezeSelected()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Unfreeze Selected Atoms"));
  action->setData(unfreezeAction);
  connect(action, SIGNAL(triggered()), SLOT(unfreezeSelected()));
  m_actions.push_back(action);

  // initialize the calculators

  // prefer to use Python interface scripts if available
  refreshScripts();

  // add the openbabel calculators in case they don't exist
#ifdef BUILD_GPL_PLUGINS
  // These directly use Open Babel and are fast
  qDebug() << " registering GPL plugins";
  Calc::EnergyManager::registerModel(new OBEnergy("MMFF94"));
  Calc::EnergyManager::registerModel(new OBEnergy("UFF"));
  Calc::EnergyManager::registerModel(new OBEnergy("GAFF"));
#else
  // These call obmm and can be slower
  qDebug() << " registering obmm plugins";
  Calc::EnergyManager::registerModel(new OBMMEnergy("MMFF94"));
  Calc::EnergyManager::registerModel(new OBMMEnergy("UFF"));
  Calc::EnergyManager::registerModel(new OBMMEnergy("GAFF"));
#endif
}

Forcefield::~Forcefield() {}

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
  auto list =
    Calc::EnergyManager::instance().identifiersForMolecule(*m_molecule);
  for (auto option : list) {
    forceFields << option.c_str();
  }

  QSettings settings;
  QVariantMap options;
  options["forcefield"] = m_methodName.c_str();
  options["nSteps"] = m_nSteps;
  options["maxSteps"] = m_maxSteps;
  options["tolerance"] = m_tolerance;
  options["gradientTolerance"] = m_gradientTolerance;
  options["autodetect"] = m_autodetect;

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
    settings.endGroup();
  }
  setupMethod();
}

void Forcefield::setMolecule(QtGui::Molecule* mol)
{
  if (mol == nullptr || m_molecule == mol)
    return;

  m_molecule = mol;
  setupMethod();
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

  if (m_method == nullptr) {
    // we have to create the calculator
    m_method = Calc::EnergyManager::instance().model(m_methodName);
  } else if (m_method->identifier() != m_methodName) {
    delete m_method; // delete the previous one
    m_method = Calc::EnergyManager::instance().model(m_methodName);
  }
  if (m_method != nullptr)
    m_method->setMolecule(m_molecule);
}

void Forcefield::optimize()
{
  if (m_molecule == nullptr)
    return;

  if (m_method == nullptr)
    setupMethod();
  if (m_method == nullptr)
    return; // bad news

  if (!m_molecule->atomCount()) {
    QMessageBox::information(nullptr, tr("Avogadro"),
                             tr("No atoms provided for optimization"));
    return;
  }

  // merge all coordinate updates into one step for undo
  bool isInteractive = m_molecule->undoMolecule()->isInteractive();
  m_molecule->undoMolecule()->setInteractive(true);

  cppoptlib::LbfgsSolver<EnergyCalculator> solver;

  int n = m_molecule->atomCount();

  // double-check the mask
  auto mask = m_molecule->frozenAtomMask();
  if (mask.rows() != 3 * n) {
    mask = Eigen::VectorXd::Zero(3 * n);
    // set to 1.0
    for (Index i = 0; i < 3 * n; ++i) {
      mask[i] = 1.0;
    }
  }
  m_method->setMolecule(m_molecule);
  m_method->setMask(mask);

  // we have to cast the current 3d positions into a VectorXd
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> map(p, 3 * n);
  Eigen::VectorXd positions = map;
  Eigen::VectorXd lastPositions = positions;

  Eigen::VectorXd gradient = Eigen::VectorXd::Zero(3 * n);
  // just to get the right size / shape
  // we'll use this to draw the force arrows later
  Core::Array<Vector3> forces = m_molecule->atomPositions3d();

  // Create a Criteria class so we can update coords every N steps
  cppoptlib::Criteria<Real> crit = cppoptlib::Criteria<Real>::defaults();

  // e.g., every N steps, update coordinates
  crit.iterations = 2;
  // we don't set function or gradient criteria
  // .. these seem to be broken in the solver code
  // .. so we handle ourselves
  solver.setStopCriteria(crit);

  Real energy = m_method->value(positions);
  m_method->gradient(positions, gradient);
  qDebug() << " initial " << energy << " gradNorm: " << gradient.norm();
  qDebug() << " maxSteps" << m_maxSteps << " steps "
           << m_maxSteps / crit.iterations;

  QProgressDialog progress(tr("Optimize Geometry"), "Cancel", 0,
                           m_maxSteps / crit.iterations);
  progress.setWindowModality(Qt::WindowModal);
  progress.setMinimumDuration(0);
  progress.setAutoClose(true);
  progress.show();

  Real currentEnergy = 0.0;
  for (unsigned int i = 0; i < m_maxSteps / crit.iterations; ++i) {
    solver.minimize(*m_method, positions);
    // update the progress dialog
    progress.setValue(i);

    qApp->processEvents(QEventLoop::AllEvents, 500);

    currentEnergy = m_method->value(positions);
    progress.setLabelText(
      tr("Energy: %L1", "force field energy").arg(currentEnergy, 0, 'f', 3));
    // get the current gradient for force visualization
    m_method->gradient(positions, gradient);
#ifndef NDEBUG
    qDebug() << " optimize " << i << currentEnergy
             << " gradNorm: " << gradient.norm();
#endif

    // update coordinates
    bool isFinite = std::isfinite(currentEnergy);
    if (isFinite) {
      const double* d = positions.data();
      bool isFinite = true;
      // casting back would be lovely...
      for (size_t i = 0; i < n; ++i) {
        if (!std::isfinite(*d) || !std::isfinite(*(d + 1)) ||
            !std::isfinite(*(d + 2))) {
          isFinite = false;
          break;
        }

        pos[i] = Vector3(*(d), *(d + 1), *(d + 2));
        d += 3;

        forces[i] = -0.1 * Vector3(gradient[3 * i], gradient[3 * i + 1],
                                   gradient[3 * i + 2]);
      }
    } else {
      // reset to last positions
      positions = lastPositions;
      gradient = Eigen::VectorXd::Zero(3 * n);
      break;
    }

    // todo - merge these into one undo step
    if (isFinite) {
      m_molecule->undoMolecule()->setAtomPositions3d(pos,
                                                     tr("Optimize Geometry"));
      m_molecule->setForceVectors(forces);
      Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Modified;
      m_molecule->emitChanged(changes);
      lastPositions = positions;

      // check for convergence
      if (fabs(gradient.maxCoeff()) < m_gradientTolerance)
        break;
      if (fabs(currentEnergy - energy) < m_tolerance)
        break;

      energy = currentEnergy;
    }

    if (progress.wasCanceled())
      break;
  }

  m_molecule->undoMolecule()->setInteractive(isInteractive);
}

void Forcefield::energy()
{
  if (m_molecule == nullptr)
    return;

  if (m_method == nullptr)
    setupMethod();
  if (m_method == nullptr)
    return; // bad news

  int n = m_molecule->atomCount();
  // we have to cast the current 3d positions into a VectorXd
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> map(p, 3 * n);
  Eigen::VectorXd positions = map;

  // now get the energy
  m_method->setMolecule(m_molecule);
  Real energy = m_method->value(positions);

  QString msg(tr("%1 Energy = %L2").arg(m_methodName.c_str()).arg(energy));
  QMessageBox::information(nullptr, tr("Avogadro"), msg);
}

void Forcefield::forces()
{
  if (m_molecule == nullptr)
    return;

  if (m_method == nullptr)
    setupMethod();
  if (m_method == nullptr)
    return; // bad news

  int n = m_molecule->atomCount();

  // double-check the mask
  auto mask = m_molecule->frozenAtomMask();
  if (mask.rows() != 3 * n) {
    mask = Eigen::VectorXd::Zero(3 * n);
    // set to 1.0
    for (Index i = 0; i < 3 * n; ++i) {
      mask[i] = 1.0;
    }
  }
  m_method->setMolecule(m_molecule);
  m_method->setMask(mask);

  // we have to cast the current 3d positions into a VectorXd
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> map(p, 3 * n);
  Eigen::VectorXd positions = map;

  Eigen::VectorXd gradient = Eigen::VectorXd::Zero(3 * n);
  // just to get the right size / shape
  // we'll use this to draw the force arrows
  Core::Array<Vector3> forces = m_molecule->atomPositions3d();

  m_method->gradient(positions, gradient);

  for (size_t i = 0; i < n; ++i) {
    forces[i] =
      -0.1 * Vector3(gradient[3 * i], gradient[3 * i + 1], gradient[3 * i + 2]);
  }

  m_molecule->setForceVectors(forces);
  Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Modified;
  m_molecule->emitChanged(changes);

  QString msg(
    tr("%1 Force Norm = %L2").arg(m_methodName.c_str()).arg(gradient.norm()));
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
    // ideally, we'd use GFN-FF but it needs tweaking
    // everything else is a ranking
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
  if (!m_molecule)
    return;

  int numAtoms = m_molecule->atomCount();
  // now freeze the specified atoms
  for (Index i = 0; i < numAtoms; ++i) {
    if (m_molecule->atomSelected(i)) {
      m_molecule->setFrozenAtom(i, true);
    }
  }
}

void Forcefield::unfreezeSelected()
{
  if (!m_molecule)
    return;

  int numAtoms = m_molecule->atomCount();
  // now freeze the specified atoms
  for (Index i = 0; i < numAtoms; ++i) {
    if (m_molecule->atomSelected(i)) {
      m_molecule->setFrozenAtom(i, false);
    }
  }
}

void Forcefield::refreshScripts()
{
  unregisterScripts();
  qDeleteAll(m_scripts);
  m_scripts.clear();

  QMultiMap<QString, QString> scriptPaths =
    QtGui::ScriptLoader::scriptList("energy");
  foreach (const QString& filePath, scriptPaths) {
    auto* model = new ScriptEnergy(filePath);
    if (model->isValid())
      m_scripts.push_back(model);
    else
      delete model;
  }

  registerScripts();
}

void Forcefield::unregisterScripts()
{
  for (QList<Calc::EnergyCalculator*>::const_iterator
         it = m_scripts.constBegin(),
         itEnd = m_scripts.constEnd();
       it != itEnd; ++it) {
    Calc::EnergyManager::unregisterModel((*it)->identifier());
  }
}

void Forcefield::registerScripts()
{
  for (QList<Calc::EnergyCalculator*>::const_iterator
         it = m_scripts.constBegin(),
         itEnd = m_scripts.constEnd();
       it != itEnd; ++it) {

    qDebug() << " register " << (*it)->identifier().c_str();

    if (!Calc::EnergyManager::registerModel((*it)->newInstance())) {
      qDebug() << "Could not register model" << (*it)->identifier().c_str()
               << "due to name conflict.";
    }
  }
}

} // namespace QtPlugins
} // namespace Avogadro
