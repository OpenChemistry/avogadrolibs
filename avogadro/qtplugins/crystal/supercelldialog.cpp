/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "supercelldialog.h"
#include "ui_supercelldialog.h"

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/molecule.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>


namespace Avogadro::QtPlugins {

SupercellDialog::SupercellDialog(QWidget* p)
  : QDialog(p), m_ui(new Ui::SupercellDialog)
{
  m_ui->setupUi(this);
}

SupercellDialog::~SupercellDialog()
{
  delete m_ui;
}

bool SupercellDialog::buildSupercell(Avogadro::QtGui::Molecule& mol)
{
  // If the user rejected, just return false
  if (this->exec() == QDialog::Rejected)
    return false;

  // Read the values
  unsigned int a = m_ui->aCellSpinBox->value();
  unsigned int b = m_ui->bCellSpinBox->value();
  unsigned int c = m_ui->cCellSpinBox->value();

  // No need to do anything if all the values are one
  if (a == 1 && b == 1 && c == 1)
    return true;

  // Run the supercell-building tool
  mol.undoMolecule()->buildSupercell(a, b, c);
  return true;
}

} // namespace Avogadro
