/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "forcefield.h"

#include <QtCore/QDebug>
#include <QtWidgets/QAction>
#include <QtWidgets/QMessageBox>

#include <avogadro/qtgui/avogadropython.h>
#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/interfacescript.h>
#include <avogadro/qtgui/interfacewidget.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/utilities.h>

#include "lennardjones.h"

#include "cppoptlib/meta.h"
#include "cppoptlib/problem.h"
#include "cppoptlib/solver/conjugatedgradientdescentsolver.h"
#include "cppoptlib/solver/gradientdescentsolver.h"
#include "cppoptlib/solver/lbfgssolver.h"

namespace Avogadro {
namespace QtPlugins {

using Avogadro::QtGui::Molecule;

const int energyAction = 0;
const int optimizeAction = 1;
const int configureAction = 2;

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
  action->setText(tr("Calculate Energy"));
  action->setData(energyAction);
  connect(action, SIGNAL(triggered()), SLOT(energy()));
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

  //@todo check m_method for a particular calculator
  cppoptlib::LbfgsSolver<LennardJones> solver;

  LennardJones lj(this->parent());
  lj.setMolecule(m_molecule);

  int n = m_molecule->atomCount();
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> map(p, 3 * n);
  Eigen::VectorXd positions = map;

  // Create a Criteria class to allow us to update coordinates
  cppoptlib::Criteria<Real> crit = cppoptlib::Criteria<Real>::defaults();
  crit.iterations = 5;
  solver.setStopCriteria(crit);

  for (unsigned int i = 0; i < m_maxSteps / crit.iterations; ++i) {
    solver.minimize(lj, positions);
    const double* d = positions.data();

    // casting would be lovely...
    for (size_t i = 0; i < n; ++i) {
      pos[i] = Vector3(*(d), *(d + 1), *(d + 2));
      d += 3;
    }
    m_molecule->undoMolecule()->setAtomPositions3d(pos, "Optimize Geometry");
    Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Modified;
    m_molecule->emitChanged(changes);
  }

  qDebug() << " energy: " << lj.value(positions);
}

void Forcefield::energy()
{
  if (!m_molecule)
    return;

  //@todo check m_method for a particular calculator
  LennardJones lj(this->parent());
  lj.setMolecule(m_molecule);

  int n = m_molecule->atomCount();
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> map(p, 3 * n);
  Eigen::VectorXd positions = map;

  QString msg(tr("Energy = %L1 kJ/mol").arg(lj.value(positions)));
  QMessageBox::information(nullptr, tr("Avogadro"), msg);
}

} // end QtPlugins
}
