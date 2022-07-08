/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molecularpropertiesdialog.h"
#include "ui_molecularpropertiesdialog.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>

using Avogadro::QtGui::Molecule;

namespace Avogadro::QtPlugins {

MolecularPropertiesDialog::MolecularPropertiesDialog(QtGui::Molecule* mol,
                                                     QWidget* parent_)
  : QDialog(parent_), m_molecule(nullptr),
    m_ui(new Ui::MolecularPropertiesDialog)
{
  m_ui->setupUi(this);

  setMolecule(mol);
}

MolecularPropertiesDialog::~MolecularPropertiesDialog()
{
  delete m_ui;
}

void MolecularPropertiesDialog::setMolecule(QtGui::Molecule* mol)
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

void MolecularPropertiesDialog::updateLabels()
{
  if (m_molecule) {
    updateMassLabel();
    updateFormulaLabel();
    m_ui->atomCountLabel->setText(QString::number(m_molecule->atomCount()));
    m_ui->bondCountLabel->setText(QString::number(m_molecule->bondCount()));
  } else {
    m_ui->molMassLabel->clear();
    m_ui->formulaLabel->clear();
    m_ui->atomCountLabel->clear();
    m_ui->bondCountLabel->clear();
  }
}

void MolecularPropertiesDialog::updateMassLabel()
{
  double mass = 0.0;
  for (size_t i = 0; i < m_molecule->atomCount(); ++i)
    mass += Core::Elements::mass(m_molecule->atom(i).atomicNumber());
  m_ui->molMassLabel->setText(QString::number(mass, 'f', 3));
}

void MolecularPropertiesDialog::updateFormulaLabel()
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

void MolecularPropertiesDialog::moleculeDestroyed()
{
  m_molecule = nullptr;
  updateLabels();
}

} // namespace Avogadro
