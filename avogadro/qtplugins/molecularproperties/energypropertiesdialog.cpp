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

#include "energypropertiesdialog.h"
#include "ui_energypropertiesdialog.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>

using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

EnergyPropertiesDialog::EnergyPropertiesDialog(QtGui::Molecule *mol,
                                                     QWidget *parent_)
  : QDialog(parent_),
    m_molecule(NULL),
    m_ui(new Ui::EnergyPropertiesDialog)
{
  m_ui->setupUi(this);

  setMolecule(mol);
}

EnergyPropertiesDialog::~EnergyPropertiesDialog()
{
  delete m_ui;
}

void EnergyPropertiesDialog::setMolecule(QtGui::Molecule *mol)
{
  if (mol == m_molecule)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = mol;

  if (!m_molecule)
    return;

  connect(m_molecule, SIGNAL(changed(unsigned int)), SLOT(updateLabels()));
  connect(m_molecule, SIGNAL(destroyed()), SLOT(moleculeDestroyed()));
  updateLabels();
}

void EnergyPropertiesDialog::updateLabels()
{
  if (m_molecule) {

    if(m_molecule->hasData("total free energy"))
      m_ui->freeEnergyLabel->setText(QString::number((m_molecule->data("total free energy").toDouble())));
    else
      m_ui->freeEnergyLabel->setText(QString("N/A"));
    if(m_molecule->hasData("total energy"))
      m_ui->totalEnergyLabel->setText(QString::number((m_molecule->data("total energy").toDouble())));
    else
      m_ui->totalEnergyLabel->setText(QString("N/A"));
  }
  else {
    m_ui->freeEnergyLabel->clear();
    m_ui->totalEnergyLabel->clear();
  }
}

void EnergyPropertiesDialog::moleculeDestroyed()
{
  m_molecule = NULL;
  updateLabels();
}

} // namespace QtPlugins
} // namespace Avogadro
