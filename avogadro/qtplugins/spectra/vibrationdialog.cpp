/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "vibrationdialog.h"

#include "ui_vibrationdialog.h"
#include "vibrationmodel.h"

#include <avogadro/core/molecule.h>

namespace Avogadro {
namespace QtPlugins {

VibrationDialog::VibrationDialog(QWidget* parent_, Qt::WindowFlags f)
  : QDialog(parent_, f), m_ui(new Ui::VibrationDialog)
{
  m_ui->setupUi(this);

  m_ui->tableView->verticalHeader()->setVisible(false);
  m_ui->tableView->horizontalHeader()->setSectionResizeMode(
    QHeaderView::Stretch);
  m_ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_ui->tableView->setSelectionMode(QAbstractItemView::ExtendedSelection);

  connect(m_ui->amplitudeSlider, SIGNAL(sliderMoved(int)),
          SIGNAL(amplitudeChanged(int)));
  connect(m_ui->startButton, SIGNAL(clicked(bool)), SIGNAL(startAnimation()));
  connect(m_ui->stopButton, SIGNAL(clicked(bool)), SIGNAL(stopAnimation()));
}

VibrationDialog::~VibrationDialog()
{
  delete m_ui;
}

void VibrationDialog::setMolecule(QtGui::Molecule* molecule)
{
  if (m_ui->tableView->selectionModel()) {
    disconnect(m_ui->tableView->selectionModel(),
               SIGNAL(currentRowChanged(QModelIndex, QModelIndex)), this,
               SLOT(selectRow(QModelIndex)));
  }

  VibrationModel* model = new VibrationModel(this);
  model->setMolecule(molecule);
  m_ui->tableView->setModel(model);
  connect(m_ui->tableView->selectionModel(),
          SIGNAL(currentRowChanged(QModelIndex, QModelIndex)),
          SLOT(selectRow(QModelIndex)));

  Core::Array<double> freqs = molecule->vibrationFrequencies();
  for (size_t i = 0; i < freqs.size(); ++i) {
    if (freqs[i] > 0.5) {
      m_ui->tableView->selectRow(static_cast<int>(i));
      emit modeChanged(i);
      break;
    }
  }
}

int VibrationDialog::currentMode() const
{
  return m_ui->tableView->currentIndex().row();
}

void VibrationDialog::selectRow(QModelIndex idx)
{
  emit modeChanged(idx.row());
}

} // End namespace QtPlugins
} // End namespace Avogadro
