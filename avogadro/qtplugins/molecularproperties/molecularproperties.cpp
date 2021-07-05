/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "molecularproperties.h"

#include "molecularpropertiesdialog.h"

#include <QtWidgets/QAction>

#include <QtCore/QStringList>

namespace Avogadro {
namespace QtPlugins {

MolecularProperties::MolecularProperties(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_action(new QAction(this)),
    m_dialog(nullptr), m_molecule(nullptr)
{
  m_action->setEnabled(true);
  m_action->setText("&Molecular...");
  connect(m_action, SIGNAL(triggered()), SLOT(showDialog()));
}

MolecularProperties::~MolecularProperties()
{
}

QString MolecularProperties::description() const
{
  return tr("View general properties of a molecule.");
}

QList<QAction*> MolecularProperties::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList MolecularProperties::menuPath(QAction*) const
{
  return QStringList() << tr("&Analysis") << tr("&Properties");
}

void MolecularProperties::setMolecule(QtGui::Molecule* mol)
{
  if (mol == m_molecule)
    return;

  m_molecule = mol;
  if (m_dialog)
    m_dialog->setMolecule(m_molecule);
}

void MolecularProperties::showDialog()
{
  if (!m_dialog) {
    m_dialog = new MolecularPropertiesDialog(
      m_molecule, qobject_cast<QWidget*>(this->parent()));
  }
  m_dialog->show();
}

} // namespace QtPlugins
} // namespace Avogadro
