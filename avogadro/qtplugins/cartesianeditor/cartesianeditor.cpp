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

#include "cartesianeditor.h"

#include "cartesianeditordialog.h"

#include <QtGui/QAction>

namespace Avogadro {
namespace QtPlugins {

CartesianEditor::CartesianEditor(QObject *parent_) :
  Avogadro::QtGui::ExtensionPlugin(parent_),
  m_dialog(NULL),
  m_molecule(NULL),
  m_action(new QAction(tr("&Cartesian Editor"), this))
{
  connect(m_action, SIGNAL(triggered()), SLOT(triggered()));
}

CartesianEditor::~CartesianEditor()
{
}

QList<QAction *> CartesianEditor::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList CartesianEditor::menuPath(QAction *) const
{
  return QStringList() << tr("&Edit");
}

void CartesianEditor::setMolecule(QtGui::Molecule *mol)
{
  m_molecule = mol;
  if (m_dialog)
    m_dialog->setMolecule(mol);
}

void CartesianEditor::triggered()
{
  if (!m_dialog) {
    m_dialog = new CartesianEditorDialog(qobject_cast<QWidget*>(parent()));
    m_dialog->setMolecule(m_molecule);
  }

  m_dialog->show();
}

} // namespace QtPlugins
} // namespace Avogadro
