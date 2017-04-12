/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "customelements.h"

#include <avogadro/qtgui/customelementdialog.h>
#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QAction>

using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

CustomElements::CustomElements(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr),
    m_reassignAction(new QAction(tr("Reassign &Custom Elements..."), this))
{
  connect(m_reassignAction, SIGNAL(triggered()), SLOT(reassign()));

  updateReassignAction();
}

CustomElements::~CustomElements()
{
}

QString CustomElements::description() const
{
  return tr("Manipulate custom element types in the current molecule.");
}

QList<QAction*> CustomElements::actions() const
{
  return QList<QAction*>() << m_reassignAction;
}

QStringList CustomElements::menuPath(QAction*) const
{
  return QStringList() << tr("&Build");
}

void CustomElements::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule != mol) {
    if (m_molecule)
      m_molecule->disconnect(this);

    m_molecule = mol;

    if (m_molecule)
      connect(m_molecule, SIGNAL(changed(uint)), SLOT(moleculeChanged(uint)));

    updateReassignAction();
  }
}

void CustomElements::moleculeChanged(unsigned int c)
{
  Molecule::MoleculeChanges changes = static_cast<Molecule::MoleculeChanges>(c);
  if (changes & Molecule::Atoms &&
      (changes & (Molecule::Added | Molecule::Modified))) {
    updateReassignAction();
  }
}

void CustomElements::reassign()
{
  if (m_molecule) {
    QtGui::CustomElementDialog::resolve(qobject_cast<QWidget*>(parent()),
                                        *m_molecule);
  }
}

void CustomElements::updateReassignAction()
{
  m_reassignAction->setEnabled(m_molecule && m_molecule->hasCustomElements());
}

} // namespace QtPlugins
} // namespace Avogadro
