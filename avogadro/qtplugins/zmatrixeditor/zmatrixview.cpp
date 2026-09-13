/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "zmatrixview.h"

#include "zmatrixmodel.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtWidgets/QHeaderView>

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
