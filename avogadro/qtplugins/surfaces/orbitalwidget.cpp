/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "orbitalwidget.h"
#include "orbitaltablemodel.h"

#include <avogadro/qtgui/richtextdelegate.h>

#include <QDebug>
#include <QSettings>

using Avogadro::QtGui::RichTextDelegate;

namespace Avogadro::QtPlugins {

OrbitalWidget::OrbitalWidget(QWidget* parent, Qt::WindowFlags f)
  : QWidget(parent, f), m_settings(0), m_quality(OQ_Low), m_isovalue(0.03),
    m_precalc_limit(true), m_precalc_range(10),
    m_tableModel(new OrbitalTableModel(this)),
    m_sortedTableModel(new OrbitalSortingProxyModel(this))
{
  ui.setupUi(this);

  setWindowTitle(tr("Molecular Orbitals"));

  m_sortedTableModel->setSourceModel(m_tableModel);

  ui.table->setModel(m_sortedTableModel);
  ui.table->horizontalHeader()->setSectionResizeMode(
    QHeaderView::ResizeToContents);
  ui.table->horizontalHeader()->setStretchLastSection(true);
  // ui.table->setItemDelegateForColumn(OrbitalTableModel::C_Status,
  //                                     new ProgressBarDelegate(this));
  ui.table->setItemDelegateForColumn(OrbitalTableModel::C_Symmetry,
                                     new RichTextDelegate(this));
  // TODO: Support orbital symmetry labels
  ui.table->hideColumn(OrbitalTableModel::C_Symmetry);
  ui.table->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

  connect(
    ui.table->selectionModel(),
    SIGNAL(selectionChanged(const QItemSelection&, const QItemSelection&)),
    this, SLOT(tableClicked(const QItemSelection&)));
  connect(ui.push_render, SIGNAL(clicked()), this, SLOT(renderClicked()));

  // TODO: Implement configure dialog
  ui.push_configure->setVisible(false);
  connect(ui.push_configure, SIGNAL(clicked()), this, SLOT(configureClicked()));
  readSettings();
}

OrbitalWidget::~OrbitalWidget()
{
  writeSettings();
}

void OrbitalWidget::readSettings()
{
  QSettings settings;
  settings.beginGroup("orbitals");
  m_quality = OrbitalQuality(settings.value("defaultQuality", 1).toInt());
  m_isovalue = settings.value("isoValue", 0.03).toDouble();
  ui.combo_quality->setCurrentIndex(
    settings.value("selectedQuality", 1).toInt());
  m_sortedTableModel->HOMOFirst(settings.value("HOMOFirst", false).toBool());
  m_precalc_limit = settings.value("precalc/limit", true).toBool();
  m_precalc_range = settings.value("precalc/range", 10).toInt();
  settings.endGroup();
}

void OrbitalWidget::writeSettings()
{
  QSettings settings;
  settings.beginGroup("orbitals");
  settings.setValue("defaultQuality", m_quality);
  settings.setValue("isoValue", m_isovalue);
  settings.setValue("selectedQuality", ui.combo_quality->currentIndex());
  settings.setValue("HOMOFirst", m_sortedTableModel->isHOMOFirst());
  settings.setValue("precalc/limit", m_precalc_limit);
  settings.setValue("precalc/range", m_precalc_range);
  settings.endGroup();
}

void OrbitalWidget::reject()
{
  hide();
}

void OrbitalWidget::configureClicked()
{
  /*
  if (!m_settings) {
    m_settings = new OrbitalSettingsDialog(this);
  }
  m_settings->setDefaultQuality(m_quality);
  m_settings->setIsoValue(m_isovalue);
  m_settings->setHOMOFirst(m_sortedTableModel->isHOMOFirst());
  m_settings->setLimitPrecalc(m_precalc_limit);
  m_settings->setPrecalcRange(m_precalc_range);
  m_settings->show();
  */
}

void OrbitalWidget::fillTable(Core::BasisSet* basis)
{
  if (basis == nullptr || m_tableModel == nullptr) {
    return;
  }

  // Populate the model
  m_tableModel->setOrbitals(basis);

  ui.table->horizontalHeader()->sectionResizeMode(
    QHeaderView::ResizeToContents);

  // Sort table
  m_sortedTableModel->sort(0, Qt::AscendingOrder);

  // // Find HOMO and scroll to it
  QModelIndex homo = m_tableModel->HOMO();
  homo = m_sortedTableModel->mapFromSource(homo);
  // qDebug() << "HOMO at: " << homo.row();
  ui.table->scrollTo(homo, QAbstractItemView::PositionAtCenter);
}

void OrbitalWidget::setQuality(OrbitalQuality q)
{
  ui.combo_quality->setCurrentIndex(int(q));
}

void OrbitalWidget::selectOrbital(unsigned int orbital)
{
  QModelIndex start = m_tableModel->index(orbital - 1, 0, QModelIndex());
  QModelIndex end = m_tableModel->index(
    orbital - 1, m_tableModel->columnCount(QModelIndex()) - 1, QModelIndex());
  QItemSelection selection(start, end);

  selection = m_sortedTableModel->mapSelectionFromSource(selection);

  ui.table->selectionModel()->clear();
  ui.table->selectionModel()->select(selection,
                                     QItemSelectionModel::SelectCurrent);
}

void OrbitalWidget::tableClicked(const QItemSelection& selected)
{
  QItemSelection mappedSelected =
    m_sortedTableModel->mapSelectionToSource(selected);

  QModelIndexList selection = mappedSelected.indexes();

  // Only one row can be selected at a time, so just check the row
  // of the first entry.
  if (selection.size() == 0)
    return;
  int orbital = selection.first().row() + 1;
  emit orbitalSelected(orbital);
}

void OrbitalWidget::renderClicked()
{
  double quality = OrbitalQualityToDouble(ui.combo_quality->currentIndex());
  QModelIndexList selection = ui.table->selectionModel()->selectedIndexes();

  // Only one row can be selected at a time, so just check the row
  // of the first entry.
  if (selection.size() == 0)
    return;

  QModelIndex first = selection.first();
  first = m_sortedTableModel->mapToSource(first);

  int orbital = first.row(); // renderRequested handles the +1
  emit renderRequested(orbital, quality);
}

double OrbitalWidget::OrbitalQualityToDouble(OrbitalQuality q)
{
  switch (q) {
    case OQ_VeryLow:
      return 0.5;
    case OQ_Low:
      return 0.35;
    case OQ_Medium:
    default:
      return 0.18;
    case OQ_High:
      return 0.10;
    case OQ_VeryHigh:
      return 0.05;
  }
}

void OrbitalWidget::setDefaults(OrbitalQuality q, double i, bool HOMOFirst)
{
  m_quality = q;
  m_isovalue = i;
  m_sortedTableModel->HOMOFirst(HOMOFirst);
  m_sortedTableModel->sort(0, Qt::AscendingOrder);
}

void OrbitalWidget::setPrecalcSettings(bool limit, int range)
{
  m_precalc_limit = limit;
  m_precalc_range = range;
}

void OrbitalWidget::initializeProgress(int orbital, int min, int max, int stage,
                                       int totalStages)
{
  m_tableModel->setOrbitalProgressRange(orbital, min, max, stage, totalStages);
}

void OrbitalWidget::nextProgressStage(int orbital, int newmin, int newmax)
{
  m_tableModel->incrementStage(orbital, newmin, newmax);
}

void OrbitalWidget::updateProgress(int orbital, int current)
{
  m_tableModel->setOrbitalProgressValue(orbital, current);
}

void OrbitalWidget::calculationComplete(int orbital)
{
  m_tableModel->finishProgress(orbital);
}

void OrbitalWidget::calculationQueued(int orbital)
{
  m_tableModel->setProgressToZero(orbital);
}

} // namespace Avogadro::QtPlugins
