/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "alchemy.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>

#include <QAction>
#include <QtCore/QSettings>
#include <QtWidgets/QDialog>
#include <QtWidgets/QInputDialog>

#include <vector>

namespace Avogadro::QtPlugins {

using Core::Array;
using Core::Elements;

Alchemy::Alchemy(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr),
    m_action(new QAction(tr("Change Elements…"), this))
{
  m_action->setProperty("menu priority", 750);

  connect(m_action, &QAction::triggered, this, &Alchemy::changeElements);
}

Alchemy::~Alchemy() {}

QList<QAction*> Alchemy::actions() const
{
  QList<QAction*> result;
  return result << m_action;
}

QStringList Alchemy::menuPath(QAction*) const
{
  return QStringList() << tr("&Build");
}

void Alchemy::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void Alchemy::changeElements()
{
  if (!m_molecule)
    return;

  // assemble the list of elements
  QStringList choices;
  for (unsigned char i = 0; i < Elements::elementCount(); ++i) {
    QString choice("%1: %2");
    choice = choice.arg(i).arg(Elements::name(i));
    choices << choice;
  }

  // get the element of the first selected atom
  unsigned char firstElement = 0;
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (m_molecule->atomSelected(i)) {
      firstElement = m_molecule->atom(i).atomicNumber();
      break;
    }
  }

  bool ok = false;
  QString currentChoice = QInputDialog::getItem(
    qobject_cast<QWidget*>(parent()), tr("Change Elements"), tr("Element:"),
    choices, static_cast<int>(firstElement), false, &ok);
  if (!ok)
    return;

  unsigned char newElement = currentChoice.section(':', 0, 0).toUShort();
  // loop through the selected atoms and change their elements
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (m_molecule->atomSelected(i))
      m_molecule->atom(i).setAtomicNumber(newElement);
  }

  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

} // namespace Avogadro::QtPlugins
