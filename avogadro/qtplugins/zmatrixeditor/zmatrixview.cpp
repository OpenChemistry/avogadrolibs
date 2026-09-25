/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "zmatrixview.h"

#include "zmatrixmodel.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtGui/QContextMenuEvent>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QMenu>

namespace Avogadro::QtPlugins {

using QtGui::Molecule;

ZMatrixView::ZMatrixView(QWidget* parent_) : QTableView(parent_)
{
  setSelectionBehavior(QAbstractItemView::SelectRows);
  setSelectionMode(QAbstractItemView::ExtendedSelection);
  setAlternatingRowColors(true);
  setCornerButtonEnabled(false);
  horizontalHeader()->setStretchLastSection(true);
  // ResizeToContents would query row size hints on every model reset, and
  // there is one row per atom. The rows are single-line either way.
  verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
}

void ZMatrixView::setZMatrixModel(ZMatrixModel* model)
{
  m_model = model;
  setModel(model);
  if (model != nullptr)
    resizeColumnsToContents();
}

void ZMatrixView::setMolecule(QtGui::Molecule* molecule)
{
  if (molecule == m_molecule)
    return;

  if (m_molecule != nullptr)
    m_molecule->disconnect(this);

  m_molecule = molecule;

  if (m_molecule != nullptr) {
    connect(m_molecule, SIGNAL(changed(unsigned int)), this,
            SLOT(updateSelectionFromMolecule(unsigned int)));
  }
}

void ZMatrixView::selectionChanged(const QItemSelection& selected,
                                   const QItemSelection& deselected)
{
  QTableView::selectionChanged(selected, deselected);

  if (m_updatingSelection || m_molecule == nullptr || m_model == nullptr)
    return;

  auto* undoMolecule = m_molecule->undoMolecule();
  if (undoMolecule == nullptr)
    return;

  m_updatingSelection = true;

  for (Index i = 0; i < m_molecule->atomCount(); ++i)
    undoMolecule->setAtomSelected(i, false);

  // The model can still be holding the previous molecule's rows when a
  // selection change arrives during a reset, so an atom named here may no
  // longer exist. Check against the molecule rather than trusting the row.
  const QModelIndexList rows = selectionModel()->selectedRows();
  for (const QModelIndex& row : rows) {
    const Index atom = m_model->atomForRow(row.row());
    if (atom != MaxIndex && atom < m_molecule->atomCount())
      undoMolecule->setAtomSelected(atom, true);
  }

  m_molecule->emitChanged(Molecule::Selection);
  m_updatingSelection = false;
}

QList<int> ZMatrixView::contextRows(const QModelIndex& index_) const
{
  const QModelIndexList selected = selectionModel()->selectedRows();

  QList<int> rows;
  for (const QModelIndex& row : selected)
    rows << row.row();

  // Right-clicking a row outside the selection acts on that row, leaving the
  // selection alone, which is how the property tables behave.
  if (!rows.contains(index_.row()))
    rows = QList<int>() << index_.row();

  return rows;
}

void ZMatrixView::contextMenuEvent(QContextMenuEvent* event)
{
  if (m_model == nullptr || m_molecule == nullptr)
    return;

  const QModelIndex clicked = indexAt(event->pos());
  if (!clicked.isValid())
    return;

  const int column = clicked.column();
  QString constrainText;
  switch (column) {
    case ZMatrixModel::DistanceColumn:
      constrainText = tr("Constrain Distance");
      break;
    case ZMatrixModel::AngleColumn:
      constrainText = tr("Constrain Angle");
      break;
    case ZMatrixModel::DihedralColumn:
      constrainText = tr("Constrain Dihedral");
      break;
    default:
      // The element and reference columns are not coordinates, so there is
      // nothing on them to constrain.
      return;
  }

  // A menu offering both halves and greying the one that would do nothing
  // says which rows are already constrained without having to read the
  // locks off the cells.
  const QList<int> rows = contextRows(clicked);
  bool anyFree = false;
  bool anyConstrained = false;
  for (int row : rows) {
    if (!m_model->hasCoordinate(row, column))
      continue;
    if (m_model->constraintFor(row, column) != nullptr)
      anyConstrained = true;
    else
      anyFree = true;
  }

  if (!anyFree && !anyConstrained)
    return; // none of these rows is measured against that far back

  QMenu menu(this);
  QAction* constrainAction = menu.addAction(constrainText);
  constrainAction->setEnabled(anyFree);
  QAction* releaseAction = menu.addAction(tr("Remove Constraint"));
  releaseAction->setEnabled(anyConstrained);

  const QAction* chosen = menu.exec(event->globalPos());
  if (chosen == nullptr)
    return;

  m_model->setConstrained(rows, column, chosen == constrainAction);
}

void ZMatrixView::updateSelectionFromMolecule(unsigned int changes)
{
  if (m_updatingSelection || m_molecule == nullptr || m_model == nullptr)
    return;
  if ((changes & Molecule::Selection) == 0)
    return;

  // The view and the model both listen to the molecule, and nothing orders
  // those two slots. If this one runs first the model still describes the
  // previous molecule, and mapping through it would hand back atoms that no
  // longer exist. Wait for the model to catch up instead -- it emits its own
  // reset, which brings the selection round again.
  if (m_model->rowCount(QModelIndex()) !=
      static_cast<int>(m_molecule->atomCount()))
    return;

  m_updatingSelection = true;

  // Walking the rows and asking each one about its atom is a single pass.
  // Walking the atoms instead would mean a reverse lookup per atom, and that
  // lookup is a scan of the row map -- quadratic in the atom count.
  QItemSelection wanted;
  const int lastColumn = ZMatrixModel::ColumnCount - 1;
  const int rows = m_model->rowCount(QModelIndex());
  for (int row = 0; row < rows; ++row) {
    const Index atom = m_model->atomForRow(row);
    if (atom < m_molecule->atomCount() && m_molecule->atomSelected(atom))
      wanted.select(m_model->index(row, 0), m_model->index(row, lastColumn));
  }

  selectionModel()->select(wanted, QItemSelectionModel::ClearAndSelect);

  m_updatingSelection = false;
}

} // namespace Avogadro::QtPlugins
