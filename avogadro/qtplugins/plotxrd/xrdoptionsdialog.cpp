/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "xrdoptionsdialog.h"
#include "ui_xrdoptionsdialog.h"

#include <QtCore/QSettings>

namespace Avogadro::QtPlugins {

XrdOptionsDialog::XrdOptionsDialog(QWidget* aParent)
  : QDialog(aParent), m_ui(new Ui::XrdOptionsDialog)
{
  m_ui->setupUi(this);

  // Read the settings
  QSettings settings;
  m_ui->spin_wavelength->setValue(
    settings.value("plotxrdoptions/wavelength", 1.505600).toDouble());
  m_ui->spin_peakWidth->setValue(
    settings.value("plotxrdoptions/peakWidth", 0.529580).toDouble());
  m_ui->spin_numDataPoints->setValue(
    settings.value("plotxrdoptions/numDataPoints", 1000).toUInt());
  m_ui->spin_max2Theta->setValue(
    settings.value("plotxrdoptions/max2Theta", 162.0).toDouble());
}

XrdOptionsDialog::~XrdOptionsDialog() = default;

double XrdOptionsDialog::wavelength() const
{
  return m_ui->spin_wavelength->value();
}

double XrdOptionsDialog::peakWidth() const
{
  return m_ui->spin_peakWidth->value();
}

size_t XrdOptionsDialog::numDataPoints() const
{
  return m_ui->spin_numDataPoints->value();
}

double XrdOptionsDialog::max2Theta() const
{
  return m_ui->spin_max2Theta->value();
}

void XrdOptionsDialog::accept()
{
  // Write the settings and accept
  QSettings settings;
  settings.setValue("plotxrdoptions/wavelength", wavelength());
  settings.setValue("plotxrdoptions/peakWidth", peakWidth());
  settings.setValue("plotxrdoptions/numDataPoints",
                    static_cast<qlonglong>(numDataPoints()));
  settings.setValue("plotxrdoptions/max2Theta", max2Theta());

  QDialog::accept();
}

} // namespace Avogadro::QtPlugins
