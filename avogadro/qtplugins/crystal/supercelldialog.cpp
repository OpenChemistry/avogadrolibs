/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "supercelldialog.h"
#include "ui_supercelldialog.h"

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QPushButton>

namespace Avogadro::QtPlugins {

SupercellDialog::SupercellDialog(QWidget* p)
  : QDialog(p), m_ui(new Ui::SupercellDialog)
{
  m_ui->setupUi(this);

  // Keep each maximum above its matching minimum so the range is never empty
  connect(m_ui->aMinSpinBox, &QDoubleSpinBox::valueChanged, this,
          &SupercellDialog::rangeChanged);
  connect(m_ui->aMaxSpinBox, &QDoubleSpinBox::valueChanged, this,
          &SupercellDialog::rangeChanged);
  connect(m_ui->bMinSpinBox, &QDoubleSpinBox::valueChanged, this,
          &SupercellDialog::rangeChanged);
  connect(m_ui->bMaxSpinBox, &QDoubleSpinBox::valueChanged, this,
          &SupercellDialog::rangeChanged);
  connect(m_ui->cMinSpinBox, &QDoubleSpinBox::valueChanged, this,
          &SupercellDialog::rangeChanged);
  connect(m_ui->cMaxSpinBox, &QDoubleSpinBox::valueChanged, this,
          &SupercellDialog::rangeChanged);

  rangeChanged();
}

SupercellDialog::~SupercellDialog()
{
  delete m_ui;
}

void SupercellDialog::rangeChanged()
{
  const bool valid = m_ui->aMaxSpinBox->value() > m_ui->aMinSpinBox->value() &&
                     m_ui->bMaxSpinBox->value() > m_ui->bMinSpinBox->value() &&
                     m_ui->cMaxSpinBox->value() > m_ui->cMinSpinBox->value();

  if (QPushButton* ok = m_ui->ok_cancel_bb->button(QDialogButtonBox::Ok))
    ok->setEnabled(valid);
}

bool SupercellDialog::buildSupercell(Avogadro::QtGui::Molecule& mol)
{
  // If the user rejected, just return false
  if (this->exec() == QDialog::Rejected)
    return false;

  // Read the values
  const Vector3 rangeMin(m_ui->aMinSpinBox->value(), m_ui->bMinSpinBox->value(),
                         m_ui->cMinSpinBox->value());
  const Vector3 rangeMax(m_ui->aMaxSpinBox->value(), m_ui->bMaxSpinBox->value(),
                         m_ui->cMaxSpinBox->value());

  // No need to do anything if the range is just the original cell
  if (rangeMin.isZero() && rangeMax == Vector3(1.0, 1.0, 1.0))
    return true;

  Core::CrystalTools::Options options = Core::CrystalTools::None;
  if (m_ui->periodicBondsCheckBox->isChecked())
    options |= Core::CrystalTools::PerceivePeriodicBonds;

  // Run the supercell-building tool
  mol.undoMolecule()->buildSupercell(rangeMin, rangeMax, options);
  return true;
}

} // namespace Avogadro::QtPlugins
