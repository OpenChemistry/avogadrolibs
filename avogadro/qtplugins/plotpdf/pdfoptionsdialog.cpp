/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "pdfoptionsdialog.h"
#include "ui_pdfoptionsdialog.h"

#include <QtCore/QSettings>

namespace Avogadro::QtPlugins {

PdfOptionsDialog::PdfOptionsDialog(QWidget* aParent)
  : QDialog(aParent)
  , m_ui(new Ui::PdfOptionsDialog)
{
  m_ui->setupUi(this);

  // Read the settings
  QSettings settings;
  m_ui->spin_maxRadius->setValue(
    settings.value("plotpdfcurveoptions/maxRadius", 10.0).toDouble());
  m_ui->spin_step->setValue(
    settings.value("plotpdfcurveoptions/step", 0.1).toDouble());
}

PdfOptionsDialog::~PdfOptionsDialog() = default;

double PdfOptionsDialog::maxRadius() const
{
  return m_ui->spin_maxRadius->value();
}

double PdfOptionsDialog::step() const
{
  return m_ui->spin_step->value();
}

void PdfOptionsDialog::accept()
{
  QSettings settings;
  settings.setValue("plotpdfcurveoptions/maxRadius", maxRadius());
  settings.setValue("plotpdfcurveoptions/step", step());
  QDialog::accept();
}

} // namespace Avogadro
