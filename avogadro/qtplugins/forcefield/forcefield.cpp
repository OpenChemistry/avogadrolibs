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

#include <avogadro/qtgui/packagemanager.h>
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

  if (m_method != nullptr)
    m_method->setMolecule(m_molecule);
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

  // TODO - use different solvers
  cppoptlib::LbfgsSolver<EnergyCalculator> solver;

  auto n = m_molecule->atomCount();
  setupConstraints();

  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  Eigen::Map<Eigen::VectorXd> map(pos[0].data(), 3 * n);
  Eigen::VectorXd positions = map;
  Eigen::VectorXd lastPositions = positions;

  Eigen::VectorXd gradient = Eigen::VectorXd::Zero(3 * n);
  // just to get the right size / shape
  // we'll use this to draw the force arrows later
  Core::Array<Vector3> forces = m_molecule->atomPositions3d();

  // Create a Criteria class so we can update coords every N steps
  cppoptlib::Criteria<Real> crit = cppoptlib::Criteria<Real>::defaults();

  // e.g., every N steps, update coordinates
  crit.iterations = 5;
  // we don't set function or gradient criteria
  // .. these seem to be broken in the solver code
  // .. so we handle ourselves
  solver.setStopCriteria(crit);

  Real energy = m_method->value(positions);
  m_method->gradient(positions, gradient);

  // debug the gradients
#ifndef NDEBUG
  for (Index i = 0; i < n; ++i) {
    qDebug() << " atom " << i << " grad: " << gradient[3 * i] << ", "
             << gradient[3 * i + 1] << ", " << gradient[3 * i + 2];
  }
#endif

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
    if (std::isfinite(currentEnergy) && positions.allFinite()) {
      Eigen::Map<Eigen::VectorXd>(pos[0].data(), 3 * n) = positions;
      Eigen::Map<Eigen::VectorXd>(forces[0].data(), 3 * n) = -0.1 * gradient;
    } else {
      qDebug() << "Non-finite energy, stopping optimization" << currentEnergy;
      // reset to last positions
      positions = lastPositions;
      gradient = Eigen::VectorXd::Zero(3 * n);
      break;
    }

    {
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

  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  Eigen::Map<Eigen::VectorXd> positions(pos[0].data(),
                                        3 * m_molecule->atomCount());

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

  auto n = m_molecule->atomCount();

  // double-check the mask
  auto mask = m_molecule->frozenAtomMask();
  if (mask.rows() != 3 * n)
    mask = Eigen::VectorXd::Ones(3 * n);
  m_method->setMolecule(m_molecule);
  m_method->setMask(mask);

  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  Eigen::Map<Eigen::VectorXd> positions(pos[0].data(), 3 * n);

  Eigen::VectorXd gradient = Eigen::VectorXd::Zero(3 * n);
  // we'll use this to draw the force arrows
  Core::Array<Vector3> forces = m_molecule->atomPositions3d();

  m_method->gradient(positions, gradient);

#ifndef NDEBUG
  qDebug() << " current gradient ";
  for (Index i = 0; i < n; ++i) {
    qDebug() << " atom " << i << " element "
             << m_molecule->atom(i).atomicNumber()
             << " grad: " << gradient[3 * i] << ", " << gradient[3 * i + 1]
             << ", " << gradient[3 * i + 2];
  }

  qDebug() << " numeric gradient ";
  m_method->finiteGradient(positions, gradient);
  for (Index i = 0; i < n; ++i) {
    qDebug() << " atom " << i << " element "
             << m_molecule->atom(i).atomicNumber()
             << " grad: " << gradient[3 * i] << ", " << gradient[3 * i + 1]
             << ", " << gradient[3 * i + 2];
  }
#endif

  Eigen::Map<Eigen::VectorXd>(forces[0].data(), 3 * n) = -0.1 * gradient;

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
    m_scripts.push_back(model);
    if (!Calc::EnergyManager::registerModel(model->newInstance())) {
      qDebug() << "Could not register energy model" << identifier
               << "due to name conflict.";
    }
  } else {
    delete model;
  }
}

} // namespace QtPlugins
} // namespace Avogadro
