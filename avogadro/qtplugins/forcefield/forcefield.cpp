/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "forcefield.h"

#include <QtCore/QDebug>
#include <QtWidgets/QAction>
#include <QtWidgets/QMessageBox>

#include <QProgressDialog>
#include <QWriteLocker>
#include <QMutex>
#include <QMutexLocker>

#include <avogadro/qtgui/avogadropython.h>
#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/interfacescript.h>
#include <avogadro/qtgui/interfacewidget.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/qtgui/utilities.h>

#include <avogadro/calc/lennardjones.h>

#include <cppoptlib/meta.h>
#include <cppoptlib/problem.h>

#include <cppoptlib/solver/lbfgssolver.h>
// not currently used
#include <cppoptlib/solver/conjugatedgradientdescentsolver.h>
#include <cppoptlib/solver/gradientdescentsolver.h>

namespace Avogadro {
namespace QtPlugins {

using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::RWMolecule;
using Avogadro::Calc::EnergyCalculator;

const int energyAction = 0;
const int optimizeAction = 1;
const int configureAction = 2;
const int freezeAction = 3;

Forcefield::Forcefield(QObject* parent_)
  : ExtensionPlugin(parent_)
  , m_molecule(nullptr)
  , m_minimizer(LBFGS)
  , m_method(0) // just Lennard-Jones for now
  , m_maxSteps(100)
  , m_outputFormat(nullptr)
{
  refreshScripts();

  QAction* action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Optimize"));
  action->setData(optimizeAction);
  connect(action, SIGNAL(triggered()), SLOT(optimize()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Energy")); // calculate energy
  action->setData(energyAction);
  connect(action, SIGNAL(triggered()), SLOT(energy()));
  m_actions.push_back(action);

  action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Freeze Atoms")); // calculate energy
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
  path << tr("&Extensions") << tr("Calculate");
  return path;
}

void Forcefield::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule == mol)
    return;

  m_molecule = mol;

  // @todo set molecule for a calculator
}

void Forcefield::refreshScripts()
{
  // call the script loader
}

void Forcefield::optimize()
{
  if (!m_molecule)
    return;

  // merge all coordinate updates into one step for undo
  bool isInteractive = m_molecule->undoMolecule()->isInteractive();
  m_molecule->undoMolecule()->setInteractive(true);

  //@todo check m_minimizer for method to use
  cppoptlib::LbfgsSolver<EnergyCalculator> solver;

  int n = m_molecule->atomCount();
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> map(p, 3 * n);
  Eigen::VectorXd positions = map;

  // Create a Criteria class to adjust stopping criteria
  cppoptlib::Criteria<Real> crit = cppoptlib::Criteria<Real>::defaults();
  // @todo allow criteria to be set
  crit.iterations = 5;
  crit.xDelta = 1.0e-4; // positions converged to 1.0e-4
  crit.fDelta = 1.0e-4; // energy converged to 1.0e-4
  solver.setStopCriteria(crit); // every 5 steps, update coordinates
  cppoptlib::Status status = cppoptlib::Status::NotStarted;

  // set the method
  //@todo check m_method for a particular calculator
  Calc::LennardJones lj;
  lj.setMolecule(m_molecule);

  for (unsigned int i = 0; i < m_maxSteps / crit.iterations; ++i) {
    solver.minimize(lj, positions);

    cppoptlib::Status currentStatus = solver.status();
    if (currentStatus != status || currentStatus == cppoptlib::Status::Continue) {
      // status has changed or minimizer hasn't converged

      // update coordinates
      const double* d = positions.data();
      // casting would be lovely...
      for (size_t i = 0; i < n; ++i) {
        pos[i] = Vector3(*(d), *(d + 1), *(d + 2));
        d += 3;
      }
      // todo - merge these into one undo step
      m_molecule->undoMolecule()->setAtomPositions3d(pos, tr("Optimize Geometry"));
      Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Modified;
      m_molecule->emitChanged(changes);
    }
  }

  qDebug() << " energy: " << lj.value(positions);

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

} // end QtPlugins
}
