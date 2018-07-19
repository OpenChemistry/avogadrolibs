/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "forcefield.h"

#include <avogadro/qtgui/avogadropython.h>
#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/interfacescript.h>
#include <avogadro/qtgui/interfacewidget.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/utilities.h>

#include <QtWidgets/QAction>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QVBoxLayout>

#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QSettings>
#include <QtCore/QStandardPaths>
#include <QtCore/QStringList>
#include <QtCore/QtPlugin>

namespace Avogadro {
namespace QtPlugins {

using Avogadro::QtGui::InterfaceScript;
using Avogadro::QtGui::InterfaceWidget;

Forcefield::Forcefield(QObject* parent_)
  : ExtensionPlugin(parent_), m_molecule(nullptr), m_outputFormat(nullptr)
{
  refreshScripts();

  QAction* action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Optimize Geometry"));
  action->setData(1);
//  connect(action, SIGNAL(triggered()), SLOT(optimizeGeometry()));
  m_actions.push_back(action);
}

Forcefield::~Forcefield()
{
}

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

void Forcefield::menuActivated()
{
}


} // end QtPlugins
}
