/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "forcefield.h"

#include <QtCore/QDebug>
#include <QtWidgets/QAction>


#include <avogadro/qtgui/avogadropython.h>
#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/interfacescript.h>
#include <avogadro/qtgui/interfacewidget.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/utilities.h>

#include "lennardjones.h"

namespace Avogadro {
namespace QtPlugins {

using Avogadro::QtGui::InterfaceScript;
using Avogadro::QtGui::InterfaceWidget;

Forcefield::Forcefield(QObject* parent_)
  : ExtensionPlugin(parent_)
  , m_molecule(nullptr)
  , m_outputFormat(nullptr)
{
  refreshScripts();

  QAction* action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Calculate Energy"));
  action->setData(1);
  connect(action, SIGNAL(triggered()), SLOT(menuActivated()));
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
  if (action->data() == 1) {
    // optimize geometry
    path << tr("&Extensions");
    return path;
  }
  path << tr("&Extensions") << tr("Force Fields");
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

void Forcefield::menuActivated() {
  if (!m_molecule)
  return;

  LennardJones lj(this->parent());
  lj.setMolecule(m_molecule);

  int n = m_molecule->atomCount();
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  double *p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> map(p, 3*n);
  Eigen::VectorXd positions = map;
  Real energy = lj.value(positions);

  qDebug() << " energy: " << energy;
}

} // end QtPlugins
}
