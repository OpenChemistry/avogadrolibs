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

#include "molecularpropertiesdialog.h"
#include "ui_molecularpropertiesdialog.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>

using Avogadro::Core::Molecule;

namespace Avogadro {
namespace QtPlugins {

MolecularPropertiesDialog::MolecularPropertiesDialog(Core::Molecule *mol,
                                                     QWidget *parent_)
  : QDialog(parent_),
    m_molecule(NULL),
    m_ui(new Ui::MolecularPropertiesDialog)
{
  m_ui->setupUi(this);

  setMolecule(mol);
}

MolecularPropertiesDialog::~MolecularPropertiesDialog()
{
  delete m_ui;
}

void MolecularPropertiesDialog::setMolecule(Core::Molecule *mol)
{
  if (mol == m_molecule)
    return;

  /// @todo For the QObject molecule...
  //  if (m_molecule)
    //  m_molecule->disconnect(this);

  m_molecule = mol;

  if (!m_molecule)
    return;

  /// @todo For the QObject molecule...
//  if (m_molecule) {
//    connect(m_molecule, SIGNAL(moleculeChanged()), SLOT(updateLabels()));
//    connect(m_molecule, SIGNAL(destroyed()), SLOT(moleculeDestroyed()));
//  }

  updateLabels();
}

void MolecularPropertiesDialog::updateLabels()
{
  if (m_molecule) {
    double mass = 0.0;
    for (size_t i = 0; i < m_molecule->atomCount(); ++i)
      mass += Core::Elements::mass(m_molecule->atom(i).atomicNumber());
    m_ui->molWeightLabel->setText(QString::number(mass, 'f', 3));

    m_ui->formulaLabel->setText(m_molecule->formula().c_str());
    m_ui->atomCountLabel->setText(QString::number(m_molecule->atomCount()));
    m_ui->bondCountLabel->setText(QString::number(m_molecule->bondCount()));
  }
  else {
    m_ui->molWeightLabel->clear();
    m_ui->formulaLabel->clear();
    m_ui->atomCountLabel->clear();
    m_ui->bondCountLabel->clear();
  }
}

void MolecularPropertiesDialog::moleculeDestroyed()
{
  m_molecule = NULL;
  updateLabels();
}

} // namespace QtPlugins
} // namespace Avogadro
