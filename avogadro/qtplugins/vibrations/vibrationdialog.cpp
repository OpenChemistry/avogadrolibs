/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vibrationdialog.h"

#include "ui_vibrationdialog.h"
#include "vibrationmodel.h"

#include <avogadro/core/molecule.h>

#include <QtCore/QAbstractItemModel>

namespace Avogadro::QtPlugins {

VibrationDialog::VibrationDialog(QWidget* parent_, Qt::WindowFlags f)
  : QDialog(parent_, f), m_ui(new Ui::VibrationDialog)
{
  m_ui->setupUi(this);

  m_ui->tableView->verticalHeader()->setVisible(true);
  m_ui->tableView->horizontalHeader()->setSectionResizeMode(
    QHeaderView::Stretch);
  m_ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
  m_ui->tableView->setSelectionMode(QAbstractItemView::ExtendedSelection);

  connect(m_ui->amplitudeSlider, SIGNAL(sliderMoved(int)),
          SIGNAL(amplitudeChanged(int)));
  connect(m_ui->startButton, SIGNAL(clicked(bool)), this,
          SLOT(changeAnimation()));
}

VibrationDialog::~VibrationDialog()
{
  delete m_ui;
}

void VibrationDialog::changeAnimation()
{
  const QString start = tr("Start Animation");
  const QString stop = tr("Stop Animation");

  if (m_ui->startButton->text() == start) {
    m_ui->startButton->setText(stop);
    m_ui->startButton->setIcon(QIcon::fromTheme("media-playback-pause"));
    emit startAnimation();
  } else {
    resetAnimationButton();
    emit stopAnimation();
  }
}

void VibrationDialog::resetAnimationButton()
{
  m_ui->startButton->setText(tr("Start Animation"));
  m_ui->startButton->setIcon(QIcon::fromTheme("media-playback-start"));
}

void VibrationDialog::setMolecule(QtGui::Molecule* molecule)
{
  if (m_ui->tableView->selectionModel()) {
    disconnect(m_ui->tableView->selectionModel(),
               SIGNAL(currentRowChanged(QModelIndex, QModelIndex)), this,
               SLOT(selectRow(QModelIndex)));
  }

  // QTableView does not take ownership of its model, so the previous one has
  // to go explicitly. This is called on every conformer change, and leaving
  // the old models parented to the dialog accumulated one per change.
  QAbstractItemModel* previous = m_ui->tableView->model();

  auto* model = new VibrationModel(this);
  model->setMolecule(molecule);
  m_ui->tableView->setModel(model);
  delete previous;

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

} // namespace Avogadro::QtPlugins
