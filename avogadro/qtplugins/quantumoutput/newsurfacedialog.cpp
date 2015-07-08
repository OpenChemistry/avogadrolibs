/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Barry E. Moore II

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "newsurfacedialog.h"

#include "ui_newsurfacedialog.h"

namespace Avogadro {
namespace QtPlugins {

NewSurfaceDialog::NewSurfaceDialog(QWidget *parent_, Qt::WindowFlags f)
  : QDialog(parent_, f), m_ui(new Ui::NewSurfaceDialog)
{
  m_ui->setupUi(this);

  connect(m_ui->surfaceCombo, SIGNAL(currentIndexChanged(int)),
          SLOT(surfaceComboChanged(int)));
  connect(m_ui->resolutionCombo, SIGNAL(currentIndexChanged(int)),
          SLOT(resolutionComboChanged(int)));
  connect(m_ui->calculateButton, SIGNAL(clicked()), SLOT(calculateClicked()));
}

NewSurfaceDialog::~NewSurfaceDialog()
{
  delete m_ui;
}

void NewSurfaceDialog::setNumberOfCubes(int numberOfCubes)
{
  if (numberOfCubes < 1)
    return;

  m_ui->moCombo->setVisible(true);
  m_ui->moCombo->clear();

  for (int i = 1; i <= numberOfCubes; ++i) {
    QString text(tr("Cube %L1", "Cube").arg(i));
    m_ui->moCombo->addItem(text);
  }
  m_ui->moCombo->setCurrentIndex(0);
}  

void NewSurfaceDialog::setNumberOfElectrons(int numberOfElectrons,
                                         int numberOfMOs)
{
  if (numberOfMOs < 1)
    return;

  // Enable the MO combos and populate them.
  m_ui->moCombo->setVisible(true);
  m_ui->moCombo->clear();
  for (int i = 1; i <= numberOfMOs; ++i) {
    QString text(tr("MO %L1", "Molecular orbital").arg(i));
    if (i == numberOfElectrons / 2)
      text += ' ' + tr("(HOMO)", "Highest occupied molecular orbital");
    if (i == numberOfElectrons / 2 + 1)
      text += ' ' + tr("(LUMO)", "Lowest unoccupied molecular orbital");
    m_ui->moCombo->addItem(text);
  }
  m_ui->moCombo->setCurrentIndex(numberOfElectrons / 2 - 1);
}

void NewSurfaceDialog::setCalculationEnabled(bool enable)
{
  m_ui->calculateButton->setEnabled(enable);
}

// Currently Working Here!
void NewSurfaceDialog::surfaceComboChanged(QString n)
{
  m_ui->moCombo->setEnabled();
  m_ui->resolutionCombo->setEnabled(n == "Electron Density"
      || n == "Molecule Orbital");
  float isoValue(0.0f);
  switch (n) {
  case "Electron Density":
    isoValue = 0.1f;
    break;
  case "Molecular Orbital":
    isoValue = 0.04f;
    break;
  case "Cube File":
  default:
    isoValue = 0.03f;
  }
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

void NewSurfaceDialog::calculateClicked()
{
  float stepSize(static_cast<float>(m_ui->resolutionSpinBox->value()));
  float isoValue(m_ui->isoValueEdit->text().toFloat());
  m_ui->calculateButton->setEnabled(false);
  if (m_ui->surfaceCombo->currentIndex() == 0)
    emit calculateElectronDensity(isoValue, stepSize);
  else if (m_ui->surfaceCombo->currentIndex() == 2)
    emit calculateCube(m_ui->moCombo->currentIndex() + 1, isoValue);
  else
    emit calculateMO(m_ui->moCombo->currentIndex() + 1, isoValue, stepSize);
}

} // End namespace QtPlugins
} // End namespace Avogadro

