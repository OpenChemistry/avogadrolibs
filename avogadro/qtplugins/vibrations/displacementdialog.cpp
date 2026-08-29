/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "displacementdialog.h"

#include "ui_displacementdialog.h"

#include <QtWidgets/QPushButton>

#include <cmath>

namespace Avogadro::QtPlugins {

DisplacementDialog::DisplacementDialog(QWidget* parent_, Qt::WindowFlags f)
  : QDialog(parent_, f), m_ui(new Ui::DisplacementDialog)
{
  m_ui->setupUi(this);

  connect(m_ui->buttonBox, SIGNAL(accepted()), SLOT(accept()));
  connect(m_ui->buttonBox, SIGNAL(rejected()), SLOT(reject()));
  connect(m_ui->scaleSpinBox, SIGNAL(valueChanged(double)),
          SLOT(updateSummary()));
  connect(m_ui->countSpinBox, SIGNAL(valueChanged(int)), SLOT(updateSummary()));

  updateSummary();
}

DisplacementDialog::~DisplacementDialog()
{
  delete m_ui;
}

void DisplacementDialog::setModeSummary(const QString& summary)
{
  m_ui->modesLabel->setText(tr("Displace along: %1").arg(summary));
}

double DisplacementDialog::scaleFactor() const
{
  return m_ui->scaleSpinBox->value();
}

int DisplacementDialog::structureCount() const
{
  return m_ui->countSpinBox->value();
}

bool DisplacementDialog::isZeroScale() const
{
  // The spin box is quantised to three decimals, so this is really an exact
  // comparison written so it does not read as one.
  return std::fabs(scaleFactor()) < 1e-9;
}

void DisplacementDialog::updateSummary()
{
  const double scale = scaleFactor();
  const int count = structureCount();

  // A zero scale factor would add coordinate sets identical to the geometry
  // that is already there. Say so rather than generating duplicates.
  if (QPushButton* ok = m_ui->buttonBox->button(QDialogButtonBox::Ok))
    ok->setEnabled(!isZeroScale());
  if (isZeroScale()) {
    m_ui->summaryLabel->setText(
      tr("A scale factor of zero would only duplicate the current geometry."));
    return;
  }

  if (count == 1) {
    m_ui->summaryLabel->setText(
      tr("One new coordinate set, displaced by %1 × the normal mode.")
        .arg(scale, 0, 'f', 3));
    return;
  }

  // Several structures are spread evenly over [-scale, +scale], so an odd
  // count puts the undisplaced geometry in the middle.
  const QString range = QString::number(std::fabs(scale), 'f', 3);
  QString text =
    tr("%1 new coordinate sets, evenly spaced from -%2 to +%2 × the normal "
       "mode.")
      .arg(count)
      .arg(range);
  if (count % 2 == 1)
    text += QLatin1Char(' ') + tr("The middle one is the undisplaced "
                                  "geometry.");
  m_ui->summaryLabel->setText(text);
}

} // namespace Avogadro::QtPlugins
