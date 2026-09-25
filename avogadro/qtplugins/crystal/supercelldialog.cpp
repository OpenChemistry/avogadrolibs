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
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>

#include <cmath>

namespace Avogadro::QtPlugins {

namespace {
/** Upper bound on the atoms a single supercell request may generate. */
const double maxSupercellAtoms = 2.0e6;
} // namespace

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
  const bool ordered =
    m_ui->aMaxSpinBox->value() > m_ui->aMinSpinBox->value() &&
    m_ui->bMaxSpinBox->value() > m_ui->bMinSpinBox->value() &&
    m_ui->cMaxSpinBox->value() > m_ui->cMinSpinBox->value();

  // The spin boxes span -100 to 100, so an unchecked range can ask for millions
  // of cells. Estimate the work with the same cell counts buildSupercell will
  // walk, rounding outwards so the estimate is never optimistic.
  double copies = 1.0;
  if (ordered) {
    const QDoubleSpinBox* mins[3] = { m_ui->aMinSpinBox, m_ui->bMinSpinBox,
                                      m_ui->cMinSpinBox };
    const QDoubleSpinBox* maxes[3] = { m_ui->aMaxSpinBox, m_ui->bMaxSpinBox,
                                       m_ui->cMaxSpinBox };
    for (int i = 0; i < 3; ++i)
      copies *= std::ceil(maxes[i]->value()) - std::floor(mins[i]->value()) + 1;
  }

  const double atoms = copies * static_cast<double>(m_atomCount);
  const bool tooLarge = ordered && atoms > maxSupercellAtoms;

  m_ui->warningLabel->setText(
    tooLarge ? tr("This range would build roughly %L1 atoms, more than the "
                  "%L2 atom limit. Narrow the range to continue.")
                 .arg(static_cast<qlonglong>(atoms))
                 .arg(static_cast<qlonglong>(maxSupercellAtoms))
             : QString());

  if (QPushButton* ok = m_ui->ok_cancel_bb->button(QDialogButtonBox::Ok))
    ok->setEnabled(ordered && !tooLarge);
}

bool SupercellDialog::buildSupercell(Avogadro::QtGui::Molecule& mol)
{
  // Re-check the range against this molecule before showing the dialog
  m_atomCount = mol.atomCount();
  rangeChanged();

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
