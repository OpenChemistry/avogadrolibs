/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2009 Marcus D. Hanwell
  Copyright 2012-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/
#include "surfacedialog.h"

#include "ui_surfacedialog.h"

namespace Avogadro {
namespace QtPlugins {

SurfaceDialog::SurfaceDialog(QWidget* parent_, Qt::WindowFlags f)
  : QDialog(parent_, f), m_ui(new Ui::SurfaceDialog)
{
  m_ui->setupUi(this);

  connect(m_ui->resolutionCombo, SIGNAL(currentIndexChanged(int)),
          SLOT(resolutionComboChanged(int)));
  connect(m_ui->calculateButton, SIGNAL(clicked()), SLOT(calculateClicked()));
}

SurfaceDialog::~SurfaceDialog()
{
  delete m_ui;
}

void SurfaceDialog::resolutionComboChanged(int n)
{
  switch (n) {
    case 0: // Very low resolution
      m_ui->resolutionDoubleSpinBox->setValue(0.5);
      m_ui->resolutionDoubleSpinBox->setEnabled(false);
      break;
    case 1: // Low resolution
      m_ui->resolutionDoubleSpinBox->setValue(0.35);
      m_ui->resolutionDoubleSpinBox->setEnabled(false);
      break;
    case 2: // Medium resolution
      m_ui->resolutionDoubleSpinBox->setValue(0.18);
      m_ui->resolutionDoubleSpinBox->setEnabled(false);
      break;
    case 3: // High resolution
      m_ui->resolutionDoubleSpinBox->setValue(0.1);
      m_ui->resolutionDoubleSpinBox->setEnabled(false);
      break;
    case 4: // Very high resolution
      m_ui->resolutionDoubleSpinBox->setValue(0.05);
      m_ui->resolutionDoubleSpinBox->setEnabled(false);
      break;
    case 5: // Custom resolution
      m_ui->resolutionDoubleSpinBox->setValue(0.18);
      m_ui->resolutionDoubleSpinBox->setEnabled(true);
      break;
    default:
      m_ui->resolutionDoubleSpinBox->setValue(0.18);
      m_ui->resolutionDoubleSpinBox->setEnabled(false);
      break;
  }
}

void SurfaceDialog::setupBasis(int numElectrons, int numMOs)
{
  if (numMOs < 1)
    return;

  m_ui->surfaceCombo->setEnabled(true);
  m_ui->surfaceCombo->clear();
  QString text("Electron Density");
  m_ui->surfaceCombo->addItem(text);
  for (int i = 1; i <= numMOs; ++i) {
    text = tr("MO %L1", "Molecular orbital").arg(i);
    if (i == numElectrons / 2)
      text += ' ' + tr("(HOMO)", "Highest occupied molecular orbital");
    if (i == numElectrons / 2 + 1)
      text += ' ' + tr("(LUMO)", "Lowest unoccupied molecular orbital");
    m_ui->surfaceCombo->addItem(text);
  }
  m_ui->surfaceCombo->setCurrentIndex(numElectrons / 2);

  m_ui->resolutionCombo->setEnabled(true);
  m_ui->isosurfaceLineEdit->setEnabled(true);
  m_ui->calculateButton->setEnabled(true);
}

void SurfaceDialog::setupCube(int numCubes)
{
  if (numCubes < 1)
    return;

  m_ui->surfaceCombo->setEnabled(true);
  m_ui->surfaceCombo->clear();
  for (int i = 1; i <= numCubes; ++i) {
    QString text(tr("Cube %L1", "Cube File").arg(i));
    m_ui->surfaceCombo->addItem(text);
  }
  m_ui->surfaceCombo->setCurrentIndex(0);

  m_ui->isosurfaceLineEdit->setEnabled(true);
  m_ui->calculateButton->setEnabled(true);
}

void SurfaceDialog::calculateClicked()
{
  float resolutionStepSize(
    static_cast<float>(m_ui->resolutionDoubleSpinBox->value()));
  float isosurfaceValue(m_ui->isosurfaceLineEdit->text().toFloat());
  m_ui->calculateButton->setEnabled(false);
  emit calculateClickedSignal(m_ui->surfaceCombo->currentIndex(),
                              isosurfaceValue, resolutionStepSize);
}

void SurfaceDialog::reenableCalculateButton()
{
  m_ui->calculateButton->setEnabled(true);
}

} // End namespace QtPlugins
} // End namespace Avogadro
