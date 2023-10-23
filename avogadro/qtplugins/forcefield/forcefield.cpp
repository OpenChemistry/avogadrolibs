/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "forcefield.h"
#include "obmmenergy.h"
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
#include <cppoptlib/solver/bfgssolver.h>
#include <cppoptlib/solver/lbfgssolver.h>
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
  /*/
  Calc::EnergyManager::registerModel(new OBMMEnergy("MMFF94"));
  Calc::EnergyManager::registerModel(new OBMMEnergy("UFF"));
  Calc::EnergyManager::registerModel(new OBMMEnergy("GAFF"));
  */

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

  cppoptlib::ConjugatedGradientDescentSolver<EnergyCalculator> solver;
  //cppoptlib::GradientDescentSolver<EnergyCalculator> solver;

  int n = m_molecule->atomCount();
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
  crit.iterations = m_nSteps;
  // we don't set function or gradient criteria
  // .. these seem to be broken in the solver code
  // .. so we handle ourselves
  solver.setStopCriteria(crit);

  // set the method
  std::string recommended = recommendedForceField();
  qDebug() << "Energy method: " << recommended.c_str();

  if (m_method == nullptr || m_method->identifier() != recommended) {
    // we have to create the calculator
    m_method = Calc::EnergyManager::instance().model(recommended);
  }
  m_method->setMolecule(m_molecule);
  auto mask = m_molecule->frozenAtomMask();
  if (mask.rows() != m_molecule->atomCount()) {
    mask = Eigen::VectorXd::Zero(3 * m_molecule->atomCount());
    // set to 1.0
    for (Index i = 0; i < 3 * m_molecule->atomCount(); ++i) {
      mask[i] = 1.0;
    }
  }
  m_method->setMask(mask);

  Real energy = m_method->value(positions);
  m_method->gradient(positions, gradient);
  qDebug() << " initial " << energy 
  << " gradNorm: " << gradient.norm()
  << " posNorm: " << positions.norm();

  Real currentEnergy = 0.0;
  for (unsigned int i = 0; i < m_maxSteps / crit.iterations; ++i) {
    solver.minimize(*m_method, positions);

    qApp->processEvents(QEventLoop::AllEvents, 500);

    currentEnergy = m_method->value(positions);
    // get the current gradient for force visualization
    m_method->gradient(positions, gradient);
    qDebug() << " optimize " << i << currentEnergy
             << " gradNorm: " << gradient.norm()
             << " posNorm: " << positions.norm();

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
      /*
      if (fabs(gradient.maxCoeff()) < m_gradientTolerance)
        break;
      if (fabs(currentEnergy - energy) < m_tolerance)
        break;
      */

      energy = currentEnergy;
    } else {
      // reset to last positions
      positions = lastPositions;
      gradient = Eigen::VectorXd::Zero(3 * n);
    }
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

  if (m_method == nullptr || m_method->identifier() != recommended) {
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
