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
  action->setText(tr("Freeze Atoms"));
  action->setData(freezeAction);
  connect(action, SIGNAL(triggered()), SLOT(freezeSelected()));
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

  // @todo set the available method list
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
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  // just to get the right size / shape
  Core::Array<Vector3> forces = m_molecule->atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> map(p, 3 * n);
  Eigen::VectorXd positions = map;
  Eigen::VectorXd gradient = Eigen::VectorXd::Zero(3 * n);

  // Create a Criteria class to adjust stopping criteria
  cppoptlib::Criteria<Real> crit = cppoptlib::Criteria<Real>::defaults();

  // e.g., every 5 steps, update coordinates
  crit.iterations = m_nSteps;
  // we don't set function or gradient criteria
  // .. these seem to be broken in the solver code
  // .. so we handle ourselves
  solver.setStopCriteria(crit);

  // set the method
  //@todo check m_method for a particular calculator
  Calc::LennardJones lj;
  lj.setMolecule(m_molecule);

  double energy = lj.value(positions);
  for (unsigned int i = 0; i < m_maxSteps / crit.iterations; ++i) {
    solver.minimize(lj, positions);

    double currentEnergy = lj.value(positions);
    lj.gradient(positions, gradient);

    // update coordinates
    const double* d = positions.data();
    // casting would be lovely...
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
  Calc::LennardJones lj;
  lj.setMolecule(m_molecule);

  int n = m_molecule->atomCount();
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> map(p, 3 * n);
  Eigen::VectorXd positions = map;

  QString msg(tr("Energy = %L1 kJ/mol").arg(lj.value(positions)));
  QMessageBox::information(nullptr, tr("Avogadro"), msg);
}

void Forcefield::freezeSelected()
{
  if (!m_molecule)
    return;

  int numAtoms = m_molecule->atomCount();
  // now freeze the specified atoms
  for (Index i = 0; i < numAtoms; ++i) {
    if (m_molecule->atomSelected(i)) {
      // m_molecule->setAtomFrozen(i, true);
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
    if (!Calc::EnergyManager::registerModel((*it)->newInstance())) {
      qDebug() << "Could not register model" << (*it)->identifier().c_str()
               << "due to name conflict.";
    }
  }
}

} // namespace QtPlugins
} // namespace Avogadro
