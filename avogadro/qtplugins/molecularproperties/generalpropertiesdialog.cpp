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

#include "generalpropertiesdialog.h"
#include "ui_generalpropertiesdialog.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>

using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

GeneralPropertiesDialog::GeneralPropertiesDialog(QtGui::Molecule *mol,
                                                     QWidget *parent_)
  : QDialog(parent_),
    m_molecule(NULL),
    m_ui(new Ui::GeneralPropertiesDialog)
{
  m_ui->setupUi(this);

  setMolecule(mol);
}

GeneralPropertiesDialog::~GeneralPropertiesDialog()
{
  delete m_ui;
}

void GeneralPropertiesDialog::setMolecule(QtGui::Molecule *mol)
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

void GeneralPropertiesDialog::updateLabels()
{
  if (m_molecule) {
    updateMassLabel();
    updateFormulaLabel();
    m_ui->atomCountLabel->setText(QString::number(m_molecule->atomCount()));
    m_ui->bondCountLabel->setText(QString::number(m_molecule->bondCount()));

    if(m_molecule->hasData("temperature"))
      m_ui->temperatureLabel->setText(QString::number((m_molecule->data("temperature").toDouble())));
    else
      m_ui->temperatureLabel->setText(QString("N/A"));
    if(m_molecule->hasData("charge"))
      m_ui->chargeLabel->setText(QString::number((m_molecule->data("charge").toInt())));
    else
      m_ui->chargeLabel->setText(QString("N/A"));
    if(m_molecule->hasData("enthalpy"))
      m_ui->enthalpyLabel->setText(QString::number((m_molecule->data("enthalpy").toDouble())));
    else
      m_ui->enthalpyLabel->setText(QString("N/A"));
    if(m_molecule->hasData("entropy"))
      m_ui->entropyLabel->setText(QString::number((m_molecule->data("entropy").toDouble())));
    else
      m_ui->entropyLabel->setText(QString("N/A"));
    if(m_molecule->hasData("multiplicity"))
      m_ui->multiplicityLabel->setText(QString::number((m_molecule->data("multiplicity").toDouble())));
    else
      m_ui->multiplicityLabel->setText(QString("N/A"));
    if(m_molecule->hasData("total dipole moment"))
      m_ui->dipoleMomentLabel->setText(QString::number((m_molecule->data("total dipole moment").toDouble())));
    else
      m_ui->dipoleMomentLabel->setText(QString("N/A"));

  }
  else {
    m_ui->molMassLabel->clear();
    m_ui->formulaLabel->clear();
    m_ui->atomCountLabel->clear();
    m_ui->bondCountLabel->clear();
    m_ui->temperatureLabel->clear();
    m_ui->chargeLabel->clear();
    m_ui->enthalpyLabel->clear();
    m_ui->multiplicityLabel->clear();
  }
}

void GeneralPropertiesDialog::updateMassLabel()
{
  double mass = 0.0;
  for (size_t i = 0; i < m_molecule->atomCount(); ++i)
    mass += Core::Elements::mass(m_molecule->atom(i).atomicNumber());
  m_ui->molMassLabel->setText(QString::number(mass, 'f', 3));
}

void GeneralPropertiesDialog::updateFormulaLabel()
{
  QString formula = QString::fromStdString(m_molecule->formula());
  QRegExp digitParser("(\\d+)");

  int ind = digitParser.indexIn(formula);
  while (ind != -1) {
    QString digits = digitParser.cap(1);
    formula.replace(ind, digits.size(), QString("<sub>%1</sub>").arg(digits));
    ind = digitParser.indexIn(formula, ind + digits.size() + 11);
  }

  m_ui->formulaLabel->setText(formula);
}

void GeneralPropertiesDialog::moleculeDestroyed()
{
  m_molecule = NULL;
  updateLabels();
}

} // namespace QtPlugins
} // namespace Avogadro
