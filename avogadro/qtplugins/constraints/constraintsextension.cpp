/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "constraintsextension.h"
#include "constraintsdialog.h"
#include "constraintsmodel.h"

#include <QAction>
#include <QDebug>

#include <string>
#include <iostream>

namespace Avogadro {
namespace QtPlugins {
ConstraintsExtension::ConstraintsExtension(QObject* p) : ExtensionPlugin(p)
{
  QAction* action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Constraints…"));
  connect(action, SIGNAL(triggered()), SLOT(openDialog()));
  m_actions.push_back(action);
}

ConstraintsExtension::~ConstraintsExtension()
{
  if (m_dialog)
    m_dialog->deleteLater();
}

QList<QAction*> ConstraintsExtension::actions() const
{
  return m_actions;
}

QStringList ConstraintsExtension::menuPath(QAction*) const
{
  return QStringList() << tr("&Extensions") << tr("&Calculate");
}

void ConstraintsExtension::openDialog()
{
  if (m_dialog == nullptr) {
    m_dialog = new ConstraintsDialog(qobject_cast<QWidget*>(parent()));
  }

  // update the constraints before we show the dialog
  if (m_molecule != nullptr)
    m_dialog->setMolecule(m_molecule);

  m_dialog->updateConstraints();

  m_dialog->show();
  m_dialog->raise();
}

void ConstraintsExtension::setMolecule(QtGui::Molecule* mol)
{
  if (mol != m_molecule) {
    m_molecule = mol;
  }

  if (m_dialog != nullptr)
    m_dialog->setMolecule(mol);
}

} // namespace QtPlugins
} // namespace Avogadro
