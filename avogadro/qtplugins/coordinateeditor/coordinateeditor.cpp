/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "coordinateeditor.h"

#include "coordinateeditordialog.h"

#include <QtWidgets/QAction>

namespace Avogadro::QtPlugins {

CoordinateEditor::CoordinateEditor(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_dialog(nullptr),
    m_molecule(nullptr),
    m_action(new QAction(tr("Atomic &Coordinate Editor…"), this))
{
  connect(m_action, SIGNAL(triggered()), SLOT(triggered()));
}

CoordinateEditor::~CoordinateEditor()
{
}

QList<QAction*> CoordinateEditor::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList CoordinateEditor::menuPath(QAction*) const
{
  return QStringList() << tr("&Build");
}

void CoordinateEditor::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
  if (m_dialog)
    m_dialog->setMolecule(mol);
}

void CoordinateEditor::triggered()
{
  if (!m_dialog) {
    m_dialog = new CoordinateEditorDialog(qobject_cast<QWidget*>(parent()));
    m_dialog->setMolecule(m_molecule);
    connect(m_dialog, SIGNAL(pastedMolecule()), SLOT(pastedMolecule()));
  }

  m_dialog->show();
}

void CoordinateEditor::pastedMolecule()
{
  // We went from no atoms to something, don't edit by default
  // PR#394
  requestActiveTool("Navigator");
}

} // namespace Avogadro
