/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2009 Marcus D. Hanwell
  Copyright 2012-2013 Kitware, Inc.
  Copyright 2018 Geoffrey Hutchison

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

  setupSteps(1);

  m_ui->orbitalCombo->setVisible(false);
  m_ui->spinCombo->setVisible(false);
  m_ui->chargeCombo->setVisible(false);
  m_ui->recordButton->setVisible(false);

  // set the data for the default items
  /* Don't add surface types that aren't available yet, uncomment once they are.
  m_ui->surfaceCombo->addItem(tr("Van der Waals"), Surfaces::Type::VanDerWaals);
  m_ui->surfaceCombo->addItem(tr("Solvent Accessible"),
                              Surfaces::Type::SolventAccessible);
  m_ui->surfaceCombo->addItem(tr("Solvent Excluded"),
                              Surfaces::Type::SolventExcluded);
  */

  connect(m_ui->surfaceCombo, SIGNAL(currentIndexChanged(int)),
          SLOT(surfaceComboChanged(int)));
  connect(m_ui->resolutionCombo, SIGNAL(currentIndexChanged(int)),
          SLOT(resolutionComboChanged(int)));
  connect(m_ui->stepValue, SIGNAL(valueChanged(int)), SIGNAL(stepChanged(int)));
  connect(m_ui->calculateButton, SIGNAL(clicked()), SLOT(calculateClicked()));
  connect(m_ui->recordButton, SIGNAL(clicked()), SLOT(record()));
}

SurfaceDialog::~SurfaceDialog()
{
  delete m_ui;
}

void SurfaceDialog::surfaceComboChanged(int n)
{
  int type = m_ui->surfaceCombo->itemData(n).toInt();
  if (type == Surfaces::Type::MolecularOrbital ||
      type == Surfaces::Type::FromFile) {
    m_ui->orbitalCombo->setEnabled(true);
  } else {
    m_ui->orbitalCombo->setEnabled(false);
  }
}

void SurfaceDialog::resolutionComboChanged(int n)
{
  // resolutions are in Angstrom
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

void SurfaceDialog::setupBasis(int numElectrons, int numMOs, bool beta)
{
  // only if we have electrons
  if (numMOs < 1)
    return;

  m_ui->orbitalCombo->setVisible(true);
  m_ui->orbitalCombo->setEnabled(false);

  m_ui->surfaceCombo->addItem(tr("Molecular Orbital"),
                              Surfaces::Type::MolecularOrbital);
  m_ui->surfaceCombo->addItem(tr("Electron Density"),
                              Surfaces::Type::ElectronDensity);

  if (beta) {
    m_ui->spinCombo->setVisible(true);
    m_ui->spinCombo->setEnabled(true);
  }
  // TODO: this class doesn't know about alpha / beta spin right now
  /*
  if (numElectrons % 2 != 0) {
    m_ui->surfaceCombo->addItem(tr("Spin Density"),
  Surfaces::Type::SpinDensity); m_ui->spinCombo->setVisible(true);
    m_ui->spinCombo->setEnabled(true);
  }
  */

  // TODO: get this from the basis information
  QString text;
  for (int i = 1; i <= numMOs; ++i) {
    text = tr("MO %L1", "Molecular orbital").arg(i);
    if (i == numElectrons / 2)
      text += ' ' + tr("(HOMO)", "Highest occupied molecular orbital");
    if (i == numElectrons / 2 + 1)
      text += ' ' + tr("(LUMO)", "Lowest unoccupied molecular orbital");
    m_ui->orbitalCombo->addItem(text);
  }

  m_ui->orbitalCombo->setCurrentIndex(numElectrons / 2);
}

void SurfaceDialog::setupCubes(QStringList cubeNames)
{
  if (cubeNames.size() < 1)
    return;

  m_ui->orbitalCombo->setVisible(true);
  m_ui->orbitalCombo->setEnabled(true);

  m_ui->surfaceCombo->addItem(tr("From File"), Surfaces::Type::FromFile);

  for (int i = 0; i < cubeNames.size(); ++i) {
    m_ui->orbitalCombo->addItem(cubeNames[i]);
  }
  m_ui->orbitalCombo->setCurrentIndex(0);
}

void SurfaceDialog::setupSteps(int stepCount)
{
  if (stepCount < 2) {
    m_ui->stepValue->setEnabled(false);
    m_ui->recordButton->setEnabled(false);
    m_ui->recordButton->setVisible(false);
    m_ui->vcrBack->setEnabled(false);
    m_ui->vcrBack->setVisible(false);
    m_ui->vcrPlay->setEnabled(false);
    m_ui->vcrPlay->setVisible(false);
    m_ui->vcrForward->setEnabled(false);
    m_ui->vcrForward->setVisible(false);
  } else {
    m_ui->stepValue->setEnabled(true);
    m_ui->stepValue->setRange(1, stepCount);
    m_ui->stepValue->setSuffix(tr(" of %0").arg(stepCount));
    m_ui->recordButton->setEnabled(true);
    m_ui->recordButton->setVisible(true);
    /* Disable for now, this would be nice in future.
    m_ui->vcrBack->setEnabled(true);
    m_ui->vcrBack->setVisible(true);
    m_ui->vcrPlay->setEnabled(true);
    m_ui->vcrPlay->setVisible(true);
    m_ui->vcrForward->setEnabled(true);
    m_ui->vcrForward->setVisible(true);
    */
  }
}

Surfaces::Type SurfaceDialog::surfaceType()
{
  return static_cast<Surfaces::Type>(m_ui->surfaceCombo->currentData().toInt());
}

int SurfaceDialog::surfaceIndex()
{
  return m_ui->orbitalCombo->currentIndex();
}

bool SurfaceDialog::beta()
{
  return m_ui->spinCombo->currentIndex() == 1;
}

float SurfaceDialog::isosurfaceValue()
{
  return static_cast<float>(m_ui->isosurfaceDoubleSpinBox->value());
}

float SurfaceDialog::resolution()
{
  return static_cast<float>(m_ui->resolutionDoubleSpinBox->value());
}

int SurfaceDialog::step()
{
  return m_ui->stepValue->value();
}

void SurfaceDialog::setStep(int step)
{
  m_ui->stepValue->setValue(step);
}

void SurfaceDialog::calculateClicked()
{
  m_ui->calculateButton->setEnabled(false);
  emit calculateClickedSignal();
}

void SurfaceDialog::reenableCalculateButton()
{
  m_ui->calculateButton->setEnabled(true);
}

void SurfaceDialog::record()
{
  m_ui->calculateButton->setEnabled(false);
  m_ui->recordButton->setEnabled(false);
  emit recordClicked();
}

void SurfaceDialog::enableRecord()
{
  m_ui->calculateButton->setEnabled(true);
  m_ui->recordButton->setEnabled(true);
}

} // End namespace QtPlugins
} // End namespace Avogadro
