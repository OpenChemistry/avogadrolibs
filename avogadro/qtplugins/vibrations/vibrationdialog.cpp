/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vibrationdialog.h"

#include "displacementdialog.h"
#include "ui_vibrationdialog.h"
#include "vibrationmodel.h"

#include <avogadro/core/molecule.h>

#include <QtCore/QAbstractItemModel>
#include <QtWidgets/QMenu>

#include <algorithm>

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

  m_ui->tableView->setContextMenuPolicy(Qt::CustomContextMenu);
  connect(m_ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this,
          SLOT(showTableContextMenu(QPoint)));

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

QList<int> VibrationDialog::selectedModes() const
{
  QList<int> modes;
  QItemSelectionModel* selection = m_ui->tableView->selectionModel();
  if (selection == nullptr)
    return modes;

  const QModelIndexList rows = selection->selectedRows();
  modes.reserve(rows.size());
  for (const QModelIndex& idx : rows)
    modes.append(idx.row());
  std::sort(modes.begin(), modes.end());
  return modes;
}

void VibrationDialog::selectRow(QModelIndex idx)
{
  emit modeChanged(idx.row());
}

void VibrationDialog::showTableContextMenu(const QPoint& point)
{
  // A right-click does not move the selection, so a click outside it is taken
  // to mean that row. Clicking inside a multi-row selection keeps it, which is
  // how several modes get displaced together.
  const QModelIndex idx = m_ui->tableView->indexAt(point);
  if (idx.isValid() && !selectedModes().contains(idx.row()))
    m_ui->tableView->selectRow(idx.row());

  if (selectedModes().isEmpty())
    return;

  QMenu menu(this);
  QAction* generate = menu.addAction(tr("Generate Displaced Coordinates…"));
  connect(generate, SIGNAL(triggered()), SLOT(requestDisplacedCoordinates()));
  menu.exec(m_ui->tableView->viewport()->mapToGlobal(point));
}

void VibrationDialog::requestDisplacedCoordinates()
{
  const QList<int> modes = selectedModes();
  if (modes.isEmpty())
    return;

  DisplacementDialog dialog(this);
  dialog.setModeSummary(modeSummary(modes));
  if (dialog.exec() != QDialog::Accepted)
    return;

  emit generateDisplacedCoordinates(modes, dialog.scaleFactor(),
                                    dialog.structureCount());
}

QString VibrationDialog::modeSummary(const QList<int>& modes) const
{
  const QAbstractItemModel* model = m_ui->tableView->model();
  QStringList parts;
  for (int mode : modes) {
    const QVariant frequency =
      model ? model->data(model->index(mode, 0), Qt::DisplayRole) : QVariant();
    bool isNumber = false;
    const double value = frequency.toDouble(&isNumber);
    if (isNumber)
      parts << tr("Mode %1 (%2 cm⁻¹)").arg(mode + 1).arg(value, 0, 'f', 1);
    else
      parts << tr("Mode %1").arg(mode + 1);
  }
  return parts.join(QStringLiteral(", "));
}

} // namespace Avogadro::QtPlugins
