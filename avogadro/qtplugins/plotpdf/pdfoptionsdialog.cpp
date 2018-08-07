/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "pdfoptionsdialog.h"
#include "ui_pdfoptionsdialog.h"

#include <QtCore/QSettings>

namespace Avogadro {
namespace QtPlugins {

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

} // namespace QtPlugins
} // namespace Avogadro
