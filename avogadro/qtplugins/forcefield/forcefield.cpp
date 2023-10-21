/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "forcefield.h"
#include "scriptenergy.h"

#include <QtCore/QDebug>
#include <QtWidgets/QAction>
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
// not currently used
#include <cppoptlib/solver/conjugatedgradientdescentsolver.h>
#include <cppoptlib/solver/gradientdescentsolver.h>

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

Forcefield::Forcefield(QObject* parent_) : ExtensionPlugin(parent_)
{
  refreshScripts();

  QAction* action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Optimize"));
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
}

Forcefield::~Forcefield() {}

QList<QAction*> Forcefield::actions() const
{
  return m_actions;
}

QStringList Forcefield::menuPath(QAction* action) const
{
  QStringList path;
  if (action->data() == optimizeAction) {
    // optimize geometry
    path << tr("&Extensions");
    return path;
  }
  path << tr("&Extensions") << tr("&Calculate");
  return path;
}

void Forcefield::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule == mol)
    return;

  m_molecule = mol;
}

void Forcefield::optimize()
{
  if (!m_molecule)
    return;

  // merge all coordinate updates into one step for undo
  bool isInteractive = m_molecule->undoMolecule()->isInteractive();
  m_molecule->undoMolecule()->setInteractive(true);

  cppoptlib::LbfgsSolver<EnergyCalculator> solver;

  int n = m_molecule->atomCount();
  // we have to cast the current 3d positions into a VectorXd
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> map(p, 3 * n);
  Eigen::VectorXd positions = map;

  Eigen::VectorXd gradient = Eigen::VectorXd::Zero(3 * n);
  // just to get the right size / shape
  // we'll use this to draw the force arrows later
  Core::Array<Vector3> forces = m_molecule->atomPositions3d();

  // Create a Criteria class so we can update coords every N steps
  cppoptlib::Criteria<Real> crit = cppoptlib::Criteria<Real>::defaults();

  // e.g., every 5 steps, update coordinates
  crit.iterations = m_nSteps;
  // we don't set function or gradient criteria
  // .. these seem to be broken in the solver code
  // .. so we handle ourselves
  solver.setStopCriteria(crit);

  // set the method
  std::string recommended = recommendedForceField();
  qDebug() << "Energy method: " << recommended.c_str();

  if (m_method == nullptr) {
    // we have to create the calculator
    m_method = Calc::EnergyManager::instance().model(recommended);
  }
  m_method->setMolecule(m_molecule);
  m_method->setMask(m_molecule->frozenAtomMask());

  Real energy = m_method->value(positions);
  for (unsigned int i = 0; i < m_maxSteps / crit.iterations; ++i) {
    solver.minimize(*m_method, positions);

    Real currentEnergy = m_method->value(positions);
    // get the current gradient for force visualization
    m_method->gradient(positions, gradient);

    // update coordinates
    const double* d = positions.data();
    // casting back would be lovely...
    for (size_t i = 0; i < n; ++i) {
      pos[i] = Vector3(*(d), *(d + 1), *(d + 2));
      d += 3;

      forces[i] = -1.0 * Vector3(gradient[3 * i], gradient[3 * i + 1],
                                 gradient[3 * i + 2]);
    }
    // todo - merge these into one undo step
    m_molecule->undoMolecule()->setAtomPositions3d(pos,
                                                   tr("Optimize Geometry"));
    m_molecule->setForceVectors(forces);
    Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Modified;
    m_molecule->emitChanged(changes);

    // check for convergence
    if (fabs(gradient.maxCoeff()) < m_gradientTolerance)
      break;
    if (fabs(currentEnergy - energy) < m_tolerance)
      break;
    energy = currentEnergy;
  }

  m_molecule->undoMolecule()->setInteractive(isInteractive);
}

void Forcefield::energy()
{
  if (!m_molecule)
    return;

  //@todo check m_method for a particular calculator
  std::string recommended = recommendedForceField();
  qDebug() << "Energy method: " << recommended.c_str();

  if (m_method == nullptr) {
    // we have to create the calculator
    m_method = Calc::EnergyManager::instance().model(recommended);
  }
  m_method->setMolecule(m_molecule);

  int n = m_molecule->atomCount();
  // we have to cast the current 3d positions into a VectorXd
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> map(p, 3 * n);
  Eigen::VectorXd positions = map;

  // now get the energy
  Real energy = m_method->value(positions);

  QString msg(tr("Energy = %L1").arg(energy));
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
  for (auto options : list) {
    // ideally, we'd use GFN-FF but it needs tweaking
    // everything else is a ranking
    // GAFF is better than MMFF94 which is better than UFF
    if (options == "UFF" && bestOption != "GAFF" || bestOption != "MMFF94")
      bestOption = options;
    if (options == "MMFF94" && bestOption != "GAFF")
      bestOption = options;
    if (options == "GAFF")
      bestOption = options;
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

  QMap<QString, QString> scriptPaths =
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
