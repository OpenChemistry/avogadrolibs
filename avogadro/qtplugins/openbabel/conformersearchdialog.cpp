/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "conformersearchdialog.h"

#include <QButtonGroup>
#include <QDebug>
#include <QPushButton>

namespace Avogadro {

ConformerSearchDialog::ConformerSearchDialog(QWidget* parent) : QDialog(parent)
{
  ui.setupUi(this);

  connect(ui.systematicRadio, SIGNAL(toggled(bool)), this,
          SLOT(systematicToggled(bool)));
  connect(ui.randomRadio, SIGNAL(toggled(bool)), this,
          SLOT(randomToggled(bool)));
  connect(ui.weightedRadio, SIGNAL(toggled(bool)), this,
          SLOT(weightedToggled(bool)));
  connect(ui.geneticRadio, SIGNAL(toggled(bool)), this,
          SLOT(geneticToggled(bool)));

  connect(ui.buttonBox, SIGNAL(clicked(QAbstractButton*)), this,
          SLOT(buttonClicked(QAbstractButton*)));

  m_method = 1; // systematic
  m_numConformers = 100;

  ui.numSpin->setValue(0);
  ui.systematicRadio->setChecked(true);
  ui.randomRadio->setChecked(false);
  ui.weightedRadio->setChecked(false);
  ui.geneticRadio->setChecked(false);
  ui.childrenSpinBox->setEnabled(false);
  ui.mutabilitySpinBox->setEnabled(false);
  ui.convergenceSpinBox->setEnabled(false);
  ui.scoringComboBox->setEnabled(false);
}

ConformerSearchDialog::~ConformerSearchDialog() {}

void ConformerSearchDialog::buttonClicked(QAbstractButton* button)
{
  if (button == ui.buttonBox->button(QDialogButtonBox::Ok)) {
    emit accepted();
  }
  close();
}

QStringList ConformerSearchDialog::options() const
{
  QStringList options;

  // in OB v3.2
  options << "--steps" << QString::number(ui.optimizationStepsSpinBox->value());

  if (ui.systematicRadio->isChecked())
    options << "--systematic";
  else if (ui.randomRadio->isChecked()) {
    options << "--random";
    options << "--nconf" << QString::number(ui.numSpin->value());
  } else if (ui.weightedRadio->isChecked()) {
    options << "--weighted";
    options << "--nconf" << QString::number(ui.numSpin->value());
  } else if (ui.geneticRadio->isChecked()) {
    // genetic is the default, no need to specify
    options << "--nconf" << QString::number(ui.numSpin->value());
    options << "--children" << QString::number(ui.childrenSpinBox->value());
    options << "--mutability" << QString::number(ui.mutabilitySpinBox->value());
    options << "--convergence"
            << QString::number(ui.convergenceSpinBox->value());
    options << "--scoring" << ui.scoringComboBox->currentText();
  }

  return options;
}

void ConformerSearchDialog::systematicToggled(bool checked)
{
  if (checked) {
    m_method = 1;
    ui.systematicRadio->setChecked(true);
    ui.randomRadio->setChecked(false);
    ui.weightedRadio->setChecked(false);
    ui.geneticRadio->setChecked(false);
    ui.childrenSpinBox->setEnabled(false);
    ui.mutabilitySpinBox->setEnabled(false);
    ui.convergenceSpinBox->setEnabled(false);
    ui.scoringComboBox->setEnabled(false);

    ui.numSpin->setEnabled(false);
    ui.numSpin->setValue(0);
  }
}

void ConformerSearchDialog::randomToggled(bool checked)
{
  if (checked) {
    m_method = 2;
    ui.systematicRadio->setChecked(false);
    ui.randomRadio->setChecked(true);
    ui.weightedRadio->setChecked(false);
    ui.geneticRadio->setChecked(false);
    ui.childrenSpinBox->setEnabled(false);
    ui.mutabilitySpinBox->setEnabled(false);
    ui.convergenceSpinBox->setEnabled(false);
    ui.scoringComboBox->setEnabled(false);
    ui.numSpin->setEnabled(true);
    ui.numSpin->setValue(100);
  }
}

void ConformerSearchDialog::weightedToggled(bool checked)
{
  if (checked) {
    m_method = 3;
    ui.systematicRadio->setChecked(false);
    ui.randomRadio->setChecked(false);
    ui.weightedRadio->setChecked(true);
    ui.geneticRadio->setChecked(false);
    ui.childrenSpinBox->setEnabled(false);
    ui.mutabilitySpinBox->setEnabled(false);
    ui.convergenceSpinBox->setEnabled(false);
    ui.scoringComboBox->setEnabled(false);
    ui.numSpin->setEnabled(true);
    ui.numSpin->setValue(100);
  }
}

void ConformerSearchDialog::geneticToggled(bool checked)
{
  if (checked) {
    m_method = 4;
    ui.systematicRadio->setChecked(false);
    ui.randomRadio->setChecked(false);
    ui.weightedRadio->setChecked(false);
    ui.geneticRadio->setChecked(true);
    ui.childrenSpinBox->setEnabled(true);
    ui.mutabilitySpinBox->setEnabled(true);
    ui.convergenceSpinBox->setEnabled(true);
    ui.scoringComboBox->setEnabled(true);
    ui.numSpin->setEnabled(true);
    ui.numSpin->setValue(100);
  }
}

void ConformerSearchDialog::accept()
{
  m_numConformers = ui.numSpin->value();
  hide();
}

void ConformerSearchDialog::reject()
{
  hide();
}

int ConformerSearchDialog::numConformers()
{
  return m_numConformers;
}

int ConformerSearchDialog::method()
{
  return m_method;
}
} // namespace Avogadro
