/******************************************************************************
  This source file is part of the MoleQueue project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "volumescalingdialog.h"
#include "ui_volumescalingdialog.h"

namespace Avogadro::QtPlugins {

VolumeScalingDialog::VolumeScalingDialog(QWidget* p)
  : QDialog(p), m_ui(new Ui::VolumeScalingDialog), m_currentVolume(0.)
{
  m_ui->setupUi(this);
  connect(m_ui->newVolume, SIGNAL(valueChanged(double)), SLOT(volumeEdited()));
  connect(m_ui->scalingFactor, SIGNAL(valueChanged(double)),
          SLOT(factorEdited()));
}

VolumeScalingDialog::~VolumeScalingDialog()
{
  delete m_ui;
}

void VolumeScalingDialog::setCurrentVolume(double vol)
{
  m_currentVolume = vol;
  m_ui->currentVolume->setText(QString::number(vol, 'f', 5));
  m_ui->newVolume->setValue(vol);
}

double VolumeScalingDialog::newVolume() const
{
  return m_ui->newVolume->value();
}

bool VolumeScalingDialog::transformAtoms() const
{
  return m_ui->transformAtoms->isChecked();
}

void VolumeScalingDialog::volumeEdited()
{
  double v = m_ui->newVolume->value();
  m_ui->scalingFactor->blockSignals(true);
  m_ui->scalingFactor->setValue(v / m_currentVolume);
  m_ui->scalingFactor->blockSignals(false);
}

void VolumeScalingDialog::factorEdited()
{
  double f = m_ui->scalingFactor->value();
  m_ui->newVolume->blockSignals(true);
  m_ui->newVolume->setValue(m_currentVolume * f);
  m_ui->newVolume->blockSignals(false);
}

} // namespace Avogadro
