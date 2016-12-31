/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2016 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "select.h"

#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QAction>
#include <QtGui/QKeySequence>

#include <QtCore/QStringList>

using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

Select::Select(QObject *parent_) :
  Avogadro::QtGui::ExtensionPlugin(parent_),
  m_molecule(nullptr)
{
  QAction *action = new QAction(tr("Select All"), this);
  action->setShortcut(QKeySequence("Ctrl+A"));
  connect(action, SIGNAL(triggered()), SLOT(selectAll()));
  m_actions.append(action);

  action = new QAction(tr("Select None"), this);
  action->setShortcut(QKeySequence("Ctrl+Shift+A"));
  connect(action, SIGNAL(triggered()), SLOT(selectNone()));
  m_actions.append(action);

  action = new QAction(this);
  action->setSeparator(true);
  m_actions.append(action);

  action = new QAction(tr("Invert Selection"), this);
  connect(action, SIGNAL(triggered()), SLOT(invertSelection()));
  m_actions.append(action);
}

Select::~Select()
{
}

QString Select::description() const
{
  return tr("Change selections");
}

QList<QAction *> Select::actions() const
{
  return m_actions;
}

QStringList Select::menuPath(QAction *) const
{
  return QStringList() << tr("&Select");
}

void Select::setMolecule(QtGui::Molecule *mol)
{
  m_molecule = mol;
}

void Select::selectAll()
{
  if (m_molecule) {
    for (Index i = 0; i < m_molecule->atomCount(); ++i)
      m_molecule->atom(i).setSelected(true);

    m_molecule->emitChanged(Molecule::Atoms);
  }
}

void Select::selectNone()
{
  if (m_molecule) {
    for (Index i = 0; i < m_molecule->atomCount(); ++i)
      m_molecule->atom(i).setSelected(false);

    m_molecule->emitChanged(Molecule::Atoms);
  }
}

void Select::invertSelection()
{
  if (m_molecule) {
    for (Index i = 0; i < m_molecule->atomCount(); ++i)
      m_molecule->atom(i).setSelected(!m_molecule->atomSelected(i));

    m_molecule->emitChanged(Molecule::Atoms);
  }
}

} // namespace QtPlugins
} // namespace Avogadro
