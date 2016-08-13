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

#include "generalpropertiesdialog.h"
#include "energypropertiesdialog.h"

#include <QtWidgets/QAction>

#include <QtCore/QStringList>

namespace Avogadro {
namespace QtPlugins {

MolecularProperties::MolecularProperties(QObject *parent_) :
  Avogadro::QtGui::ExtensionPlugin(parent_),
  m_actions(QList<QAction *>()),
  m_dialog(NULL),
  m_Edialog(NULL),
  m_molecule(NULL),
  m_GeneralPropertyAction(new QAction(this)),
  m_EnergyPropertyAction(new QAction(this))
{
  m_GeneralPropertyAction->setText(tr("General Properties"));
  connect(m_GeneralPropertyAction, SIGNAL(triggered()),
          SLOT(showGeneralDialog()));
  m_actions.push_back(m_GeneralPropertyAction);

  m_EnergyPropertyAction->setText(tr("Energy Properties"));
  connect(m_EnergyPropertyAction, SIGNAL(triggered()),
          SLOT(showEnergyDialog()));
  m_actions.push_back(m_EnergyPropertyAction);

  updateActions();
  // m_action->setEnabled(true);
  // m_action->setText("&General Properties");
  // connect(m_action, SIGNAL(triggered()), SLOT(showDialog()));
}

MolecularProperties::~MolecularProperties()
{
}

QString MolecularProperties::description() const
{
  return tr("View different properties of a molecule.");
}

QList<QAction *> MolecularProperties::actions() const
{
  return m_actions;
}

QStringList MolecularProperties::menuPath(QAction *) const
{
  QStringList path;
  path << tr("&View") << tr("Molecular Properties");
  return path;
}

void MolecularProperties::setMolecule(QtGui::Molecule *mol)
{
  if (mol == m_molecule)
    return;

  m_molecule = mol;
  if (m_dialog)
    m_dialog->setMolecule(m_molecule);
  if (m_Edialog)
    m_Edialog->setMolecule(m_molecule);
}

void MolecularProperties::updateActions()
{
  foreach (QAction *action, m_actions)
    action->setEnabled(true);
}

void MolecularProperties::showGeneralDialog()
{
  if (!m_dialog) {
    m_dialog = new GeneralPropertiesDialog(
          m_molecule, qobject_cast<QWidget*>(this->parent()));
  }
  m_dialog->show();
}

void MolecularProperties::showEnergyDialog()
{
  if (!m_Edialog) {
    m_Edialog = new EnergyPropertiesDialog(
          m_molecule, qobject_cast<QWidget*>(this->parent()));
  }
  m_Edialog->show();
}

} // namespace QtPlugins
} // namespace Avogadro
