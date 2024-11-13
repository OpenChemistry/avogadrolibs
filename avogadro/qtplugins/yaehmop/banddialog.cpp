/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "banddialog.h"

#include "ui_banddialog.h"

#include <QSettings>

namespace Avogadro::QtPlugins {

BandDialog::BandDialog(QWidget* aParent, YaehmopSettings& yaehmopSettings)
  : QDialog(aParent), m_ui(new Ui::BandDialog),
    m_yaehmopSettings(yaehmopSettings)
{
  m_ui->setupUi(this);
}

// Destructor must be defined after Ui::BandDialog has been resovled
BandDialog::~BandDialog() = default;

int BandDialog::exec()
{
  // Load the settings then exec
  m_ui->spin_numKPoints->setValue(m_yaehmopSettings.numBandKPoints);
  m_ui->edit_specialKPoints->setText(m_yaehmopSettings.specialKPoints);
  m_ui->cb_displayYaehmopInput->setChecked(
    m_yaehmopSettings.displayYaehmopInput);
  m_ui->cb_limitY->setChecked(m_yaehmopSettings.limitY);
  m_ui->spin_minY->setValue(m_yaehmopSettings.minY);
  m_ui->spin_maxY->setValue(m_yaehmopSettings.maxY);
  m_ui->cb_plotFermi->setChecked(m_yaehmopSettings.plotFermi);
  m_ui->spin_fermi->setValue(m_yaehmopSettings.fermi);
  m_ui->cb_zeroFermi->setChecked(m_yaehmopSettings.zeroFermi);
  m_ui->spin_numDim->setValue(m_yaehmopSettings.numDim);

  return QDialog::exec();
}

void BandDialog::accept()
{
  // Save the settings and accept
  m_yaehmopSettings.numBandKPoints = m_ui->spin_numKPoints->value();
  m_yaehmopSettings.specialKPoints = m_ui->edit_specialKPoints->toPlainText();
  m_yaehmopSettings.displayYaehmopInput =
    m_ui->cb_displayYaehmopInput->isChecked();
  m_yaehmopSettings.limitY = m_ui->cb_limitY->isChecked();
  m_yaehmopSettings.minY = m_ui->spin_minY->value();
  m_yaehmopSettings.maxY = m_ui->spin_maxY->value();
  m_yaehmopSettings.plotFermi = m_ui->cb_plotFermi->isChecked();
  m_yaehmopSettings.fermi = m_ui->spin_fermi->value();
  m_yaehmopSettings.zeroFermi = m_ui->cb_zeroFermi->isChecked();
  m_yaehmopSettings.numDim = m_ui->spin_numDim->value();

  QDialog::accept();
}

} // namespace Avogadro::QtPlugins
