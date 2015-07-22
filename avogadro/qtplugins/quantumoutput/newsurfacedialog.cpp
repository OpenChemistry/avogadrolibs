#include "newsurfacedialog.h"

#include "ui_newsurfacedialog.h"

namespace Avogadro {
namespace QtPlugins {

NewSurfaceDialog::NewSurfaceDialog(QWidget *parent_, Qt::WindowFlags f)
  : QDialog(parent_, f), m_ui(new Ui::NewSurfaceDialog)
{
  m_ui->setupUi(this);
  m_ui->showButton->setEnabled(true);

  connect(m_ui->surfaceTypeCombo, SIGNAL(currentIndexChanged(int)),
          SLOT(surfaceTypeComboChanged(int)));
  connect(m_ui->resolutionCombo, SIGNAL(currentIndexChanged(int)),
          SLOT(resolutionComboChanged(int)));
  connect(m_ui->surfaceCombo, SIGNAL(currentIndexChanged(int)),
          SLOT(surfaceComboChanged(int)));
  connect(m_ui->displayCombo, SIGNAL(currentIndexChanged(int)),
          SLOT(displayComboChanged(int)));
  connect(m_ui->showButton, SIGNAL(clicked()), SLOT(showClicked()));
  connect(m_ui->calculateButton, SIGNAL(clicked()), SLOT(calculateClicked()));
}

NewSurfaceDialog::~NewSurfaceDialog()
{
  delete m_ui;
}

void NewSurfaceDialog::surfaceTypeComboChanged(int n)
{
  float isoValue(0.0f);
  m_ui->isoValueEdit->setText(QString::number(isoValue));
}

void NewSurfaceDialog::resolutionComboChanged(int n)
{
  switch (n) {
  case 0: // Very low resolution
    m_ui->resolutionSpinBox->setValue(0.5);
    m_ui->resolutionSpinBox->setEnabled(false);
    break;
  case 1: // Low resolution
    m_ui->resolutionSpinBox->setValue(0.35);
    m_ui->resolutionSpinBox->setEnabled(false);
    break;
  case 2: // Medium resolution
    m_ui->resolutionSpinBox->setValue(0.18);
    m_ui->resolutionSpinBox->setEnabled(false);
    break;
  case 3: // High resolution
    m_ui->resolutionSpinBox->setValue(0.1);
    m_ui->resolutionSpinBox->setEnabled(false);
    break;
  case 4: // Very high resolution
    m_ui->resolutionSpinBox->setValue(0.05);
    m_ui->resolutionSpinBox->setEnabled(false);
    break;
  case 5: // Custom resolution
    m_ui->resolutionSpinBox->setValue(0.18);
    m_ui->resolutionSpinBox->setEnabled(true);
    break;
  default:
    m_ui->resolutionSpinBox->setValue(0.18);
    m_ui->resolutionSpinBox->setEnabled(false);
    break;
  }
}

void NewSurfaceDialog::surfaceComboChanged(int n)
{
  // This function does nothing
}

void NewSurfaceDialog::displayComboChanged(int n)
{
  // This function does nothing
}

void NewSurfaceDialog::showClicked()
{
  emit showSurface();
}

void NewSurfaceDialog::calculateClicked()
{
  // This function does nothing
}

} // End namespace QtPlugins
} // End namespace Avogadro
