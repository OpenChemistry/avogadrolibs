/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "hydrogens.h"

#include <avogadro/qtgui/hydrogentools.h>
#include <avogadro/qtgui/molecule.h>

#include <QtGui/QKeySequence>
#include <QtWidgets/QAction>

#include <QtCore/QStringList>

namespace Avogadro::QtPlugins {

Hydrogens::Hydrogens(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr)
{
  auto* action = new QAction(tr("&Adjust Hydrogens"), this);
  action->setShortcut(QKeySequence("Ctrl+Alt+H"));
  connect(action, SIGNAL(triggered()), SLOT(adjustHydrogens()));
  m_actions.append(action);

  action = new QAction(tr("Add Hydrogens"), this);
  connect(action, SIGNAL(triggered()), SLOT(addHydrogens()));
  m_actions.append(action);

  action = new QAction(tr("Remove E&xtra Hydrogens"), this);
  connect(action, SIGNAL(triggered()), SLOT(removeHydrogens()));
  m_actions.append(action);

  action = new QAction(tr("&Remove All Hydrogens"), this);
  connect(action, SIGNAL(triggered()), SLOT(removeAllHydrogens()));
  m_actions.append(action);
}

Hydrogens::~Hydrogens()
{
}

QString Hydrogens::description() const
{
  return tr("Add/remove hydrogens from the current molecule.");
}

QList<QAction*> Hydrogens::actions() const
{
  return m_actions;
}

QStringList Hydrogens::menuPath(QAction*) const
{
  return QStringList() << tr("&Build") << tr("&Hydrogens");
}

void Hydrogens::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void Hydrogens::adjustHydrogens()
{
  if (m_molecule) {
    QtGui::HydrogenTools::adjustHydrogens(*(m_molecule->undoMolecule()),
                                          QtGui::HydrogenTools::AddAndRemove);
    // Assume molecule changes...
    m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Bonds |
                            QtGui::Molecule::Added | QtGui::Molecule::Removed);
  }
}

void Hydrogens::addHydrogens()
{
  if (m_molecule) {
    QtGui::HydrogenTools::adjustHydrogens(*(m_molecule->undoMolecule()),
                                          QtGui::HydrogenTools::Add);
    // Assume molecule changes...
    m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Bonds |
                            QtGui::Molecule::Added);
  }
}

void Hydrogens::removeHydrogens()
{
  if (m_molecule) {
    QtGui::HydrogenTools::adjustHydrogens(*(m_molecule->undoMolecule()),
                                          QtGui::HydrogenTools::Remove);
    // Assume molecule changes...
    m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Bonds |
                            QtGui::Molecule::Removed);
  }
}

void Hydrogens::removeAllHydrogens()
{
  if (m_molecule) {
    QtGui::HydrogenTools::removeAllHydrogens(*(m_molecule->undoMolecule()));
    // Assume molecule changes...
    m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Bonds |
                            QtGui::Molecule::Removed);
  }
}

} // namespace Avogadro
