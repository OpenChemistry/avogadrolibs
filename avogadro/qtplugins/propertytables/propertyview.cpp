/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "propertyview.h"

#include <avogadro/qtgui/molecule.h>

#include <QtCore/QAbstractTableModel>
#include <QtCore/QSortFilterProxyModel>
#include <QtWidgets/QAction>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QScrollBar>
#include <QtWidgets/QSizePolicy>
#include <QtWidgets/QVBoxLayout>

#include <QtCore/QDebug>

namespace Avogadro {

using QtGui::Molecule;

PropertyView::PropertyView(PropertyType type, QWidget* parent)
  : QTableView(parent), m_molecule(nullptr), m_type(type), m_model(nullptr)
{
  QString title;
  switch (type) {
    case AtomType:
      title = tr("Atom Properties");
      break;
    case BondType:
      title = tr("Bond Properties");
      break;
    case AngleType:
      title = tr("Angle Properties");
      break;
    case TorsionType:
      title = tr("Torsion Properties");
      break;
    case ConformerType:
      title = tr("Conformer Properties");
      break;
    case ResidueType:
      title = tr("Residue Properties");
      break;
    default:
      title = tr("Molecule Properties");
      break;
  }
  this->setWindowTitle(title);

  QHeaderView* horizontal = this->horizontalHeader();
  horizontal->setSectionResizeMode(QHeaderView::Interactive);
  horizontal->setMinimumSectionSize(75);
  QHeaderView* vertical = this->verticalHeader();
  vertical->setSectionResizeMode(QHeaderView::Interactive);
  vertical->setMinimumSectionSize(30);
  vertical->setDefaultAlignment(Qt::AlignCenter);

  // You can select everything (e.g., to copy, select all, etc.)
  setCornerButtonEnabled(true);
  setSelectionBehavior(QAbstractItemView::SelectRows);
  setSelectionMode(QAbstractItemView::ExtendedSelection);
  // Alternating row colors
  setAlternatingRowColors(true);
  // Allow sorting the table
  setSortingEnabled(true);
}

void PropertyView::selectionChanged(const QItemSelection& selected,
                                    const QItemSelection&)
{
  bool ok = false;
  if (m_molecule == nullptr)
    return;

  // Start by clearing the molecule selection
  for (Index i = 0; i < m_molecule->atomCount(); ++i)
    m_molecule->atom(i).setSelected(false);

  foreach (const QModelIndex& index, selected.indexes()) {
    if (!index.isValid())
      return;

    // Since the user can sort
    // we need to find the original index
    int rowNum = model()
                   ->headerData(index.row(), Qt::Vertical)
                   .toString()
                   .split(" ")
                   .last()
                   .toLong(&ok) -
                 1;
    if (!ok)
      return;

    if (m_type == PropertyType::AtomType) {
      if (rowNum >= m_molecule->atomCount())
        return;

      m_molecule->setAtomSelected(rowNum, true);
    } else if (m_type == PropertyType::BondType) {
      if (rowNum >= m_molecule->bondCount())
        return;

      auto bondPair = m_molecule->bondPair(rowNum);
      m_molecule->setAtomSelected(bondPair.first, true);
      m_molecule->setAtomSelected(bondPair.second, true);
    } else if (m_type == PropertyType::AngleType) {

      if (m_model != nullptr) {
        auto angle = m_model->getAngle(index.row());
        m_molecule->setAtomSelected(std::get<0>(angle), true);
        m_molecule->setAtomSelected(std::get<1>(angle), true);
        m_molecule->setAtomSelected(std::get<2>(angle), true);
      }
    } else if (m_type == PropertyType::TorsionType) {

      if (m_model != nullptr) {
        auto torsion = m_model->getTorsion(index.row());
        m_molecule->setAtomSelected(std::get<0>(torsion), true);
        m_molecule->setAtomSelected(std::get<1>(torsion), true);
        m_molecule->setAtomSelected(std::get<2>(torsion), true);
        m_molecule->setAtomSelected(std::get<3>(torsion), true);
      }
    }
  } // end loop through selected

  m_molecule->emitChanged(Molecule::Atoms);
}

void PropertyView::setMolecule(Molecule* molecule)
{
  m_molecule = molecule;
}

void PropertyView::hideEvent(QHideEvent*)
{
  if (model()) {
    model()->deleteLater();
  }

  this->deleteLater();
}

} // end namespace Avogadro
