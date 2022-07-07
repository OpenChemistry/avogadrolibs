/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vibrationdialog.h"

#include "ui_vibrationdialog.h"
#include "vibrationmodel.h"

#include <avogadro/core/molecule.h>

namespace Avogadro::QtPlugins {

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

  auto* model = new VibrationModel(this);
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

} // End namespace Avogadro
