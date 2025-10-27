/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "propertyview.h"
#include "core/avogadrocore.h"

#include <avogadro/core/residue.h>
#include <avogadro/qtgui/molecule.h>

#include <QAction>
#include <QApplication>
#include <QtCore/QAbstractTableModel>
#include <QtCore/QDir>
#include <QtCore/QIODevice>
#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QString>
#include <QtCore/QTextStream>
#include <QtGui/QClipboard>
#include <QtGui/QContextMenuEvent>
#include <QtGui/QKeyEvent>
#include <QtWidgets/QMenu>

#include <QtWidgets/QDialog>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QScrollBar>
#include <QtWidgets/QSizePolicy>
#include <QtWidgets/QVBoxLayout>

#include <QtCore/QDebug>

namespace Avogadro {

using QtGui::Molecule;

PropertyView::PropertyView(PropertyType type, QWidget* parent)
  : QTableView(parent), m_type(type), m_molecule(nullptr), m_model(nullptr)
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
  if (type == ConformerType)
    setSelectionMode(QAbstractItemView::SingleSelection);
  else
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
    m_molecule->undoMolecule()->setAtomSelected(i, false);

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
      if (static_cast<Index>(rowNum) >= m_molecule->atomCount())
        return;

      m_molecule->setAtomSelected(rowNum, true);
    } else if (m_type == PropertyType::BondType) {
      if (static_cast<Index>(rowNum) >= m_molecule->bondCount())
        return;

      auto bondPair = m_molecule->bondPair(rowNum);
      m_molecule->undoMolecule()->setAtomSelected(bondPair.first, true);
      m_molecule->undoMolecule()->setAtomSelected(bondPair.second, true);
    } else if (m_type == PropertyType::AngleType) {

      if (m_model != nullptr) {
        auto angle = m_model->getAngle(rowNum);
        m_molecule->undoMolecule()->setAtomSelected(std::get<0>(angle), true);
        m_molecule->undoMolecule()->setAtomSelected(std::get<1>(angle), true);
        m_molecule->undoMolecule()->setAtomSelected(std::get<2>(angle), true);
      }
    } else if (m_type == PropertyType::TorsionType) {

      if (m_model != nullptr) {
        auto torsion = m_model->getTorsion(rowNum);
        m_molecule->undoMolecule()->setAtomSelected(std::get<0>(torsion), true);
        m_molecule->undoMolecule()->setAtomSelected(std::get<1>(torsion), true);
        m_molecule->undoMolecule()->setAtomSelected(std::get<2>(torsion), true);
        m_molecule->undoMolecule()->setAtomSelected(std::get<3>(torsion), true);
      }
    } else if (m_type == PropertyType::ResidueType) {
      // select all the atoms in the residue
      if (m_model != nullptr) {
        const auto residue = m_molecule->residue(rowNum);
        auto atoms = residue.residueAtoms();
        for (Index i = 0; i < atoms.size(); ++i) {
          const auto atom = atoms[i];
          m_molecule->undoMolecule()->setAtomSelected(atom.index(), true);
        }
      }
    } else if (m_type == PropertyType::ConformerType) {
      // selecting a row means switching to that conformer
      m_molecule->setCoordinate3d(rowNum);
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

void PropertyView::keyPressEvent(QKeyEvent* event)
{
  // handle copy event
  // thanks to https://www.walletfox.com/course/qtableviewcopypaste.php
  if (!event->matches(QKeySequence::Copy)) {
    QTableView::keyPressEvent(event);
    return;
  }

  // get the selected rows (if any)
  QModelIndexList selectedRows = selectionModel()->selectedRows();

  // if nothing is selected, copy everything to the clipboard
  QString text;
  if (selectedRows.isEmpty()) {
    // iterate through every row and column and copy the data
    for (int i = 0; i < model()->rowCount(); ++i) {
      QStringList rowContents;
      for (int j = 0; j < model()->columnCount(); ++j)
        rowContents << model()->index(i, j).data().toString();
      text += rowContents.join("\t");
      text += "\n";
    }
  } else {
    // copy the selected rows to the clipboard
    QItemSelectionRange range = selectionModel()->selection().first();
    for (auto i = range.top(); i <= range.bottom(); ++i) {
      QStringList rowContents;
      for (auto j = range.left(); j <= range.right(); ++j)
        rowContents << model()->index(i, j).data().toString();
      text += rowContents.join("\t");
      text += "\n";
    }
  }
  QApplication::clipboard()->setText(text);
}

void PropertyView::copySelectedRowsToClipboard()
{
  // get the selected rows (if any)
  QModelIndexList selectedRows = selectionModel()->selectedRows();

  // if nothing is selected, copy everything to the clipboard
  QString text;
  if (selectedRows.isEmpty()) {
    // iterate through every row and column and copy the data
    for (int i = 0; i < model()->rowCount(); ++i) {
      QStringList rowContents;
      for (int j = 0; j < model()->columnCount(); ++j)
        rowContents << model()->index(i, j).data().toString();
      text += rowContents.join("\t");
      text += "\n";
    }
  } else {
    // copy the selected rows to the clipboard
    QItemSelectionRange range = selectionModel()->selection().first();
    for (auto i = range.top(); i <= range.bottom(); ++i) {
      QStringList rowContents;
      for (auto j = range.left(); j <= range.right(); ++j)
        rowContents << model()->index(i, j).data().toString();
      text += rowContents.join("\t");
      text += "\n";
    }
  }
  QApplication::clipboard()->setText(text);
}

void PropertyView::constrainSelectedRows()
{
  // get the selected rows (if any)
  QModelIndexList selectedRows = selectionModel()->selectedRows();

  // if nothing is selected, we're done
  if (selectedRows.isEmpty())
    return;

  if (m_molecule == nullptr)
    return;

  // loop through the selected rows
  for (const auto& index : selectedRows) {
    if (!index.isValid())
      continue;

    // get the row number
    bool ok;
    int rowNum = model()
                   ->headerData(index.row(), Qt::Vertical)
                   .toString()
                   .split(" ")
                   .last()
                   .toLong(&ok) -
                 1;
    if (!ok)
      continue;

    if (m_type == PropertyType::BondType) {
      // get the start and end atoms and the distance from the table data
      auto bond = m_molecule->bond(rowNum);
      auto atom1 = bond.atom1();
      auto atom2 = bond.atom2();
      Real distance = bond.length();
      m_molecule->addConstraint(distance, atom1.index(), atom2.index());
    } else if (m_type == PropertyType::AngleType) {
      if (m_model != nullptr) {
        auto angle = m_model->getAngle(rowNum);
        auto atom1 = m_molecule->atom(std::get<0>(angle));
        auto atom2 = m_molecule->atom(std::get<1>(angle));
        auto atom3 = m_molecule->atom(std::get<2>(angle));
        Real angleValue = m_model->getAngleValue(rowNum);
        m_molecule->addConstraint(angleValue, atom1.index(), atom2.index(),
                                  atom3.index());
      }
    } else if (m_type == PropertyType::TorsionType) {
      if (m_model != nullptr) {
        auto torsion = m_model->getTorsion(rowNum);
        auto atom1 = m_molecule->atom(std::get<0>(torsion));
        auto atom2 = m_molecule->atom(std::get<1>(torsion));
        auto atom3 = m_molecule->atom(std::get<2>(torsion));
        auto atom4 = m_molecule->atom(std::get<3>(torsion));
        Real torsionValue = m_model->getTorsionValue(rowNum);
        m_molecule->addConstraint(torsionValue, atom1.index(), atom2.index(),
                                  atom3.index(), atom4.index());
      }
    }
  }
}

void PropertyView::unconstrainSelectedRows()
{
  // get the selected rows (if any)
  QModelIndexList selectedRows = selectionModel()->selectedRows();

  // if nothing is selected, we're done
  if (selectedRows.isEmpty())
    return;

  if (m_molecule == nullptr)
    return;

  // loop through the selected rows
  for (const auto& index : selectedRows) {
    if (!index.isValid())
      continue;

    // get the row number
    bool ok;
    int rowNum = model()
                   ->headerData(index.row(), Qt::Vertical)
                   .toString()
                   .split(" ")
                   .last()
                   .toLong(&ok) -
                 1;
    if (!ok)
      continue;

    if (m_type == PropertyType::BondType) {
      // get the start and end atoms and the distance from the table data
      auto bond = m_molecule->bond(rowNum);
      auto atom1 = bond.atom1();
      auto atom2 = bond.atom2();
      m_molecule->removeConstraint(atom1.index(), atom2.index());
    } else if (m_type == PropertyType::AngleType) {
      if (m_model != nullptr) {
        auto angle = m_model->getAngle(rowNum);
        auto atom1 = m_molecule->atom(std::get<0>(angle));
        auto atom2 = m_molecule->atom(std::get<1>(angle));
        auto atom3 = m_molecule->atom(std::get<2>(angle));
        m_molecule->removeConstraint(atom1.index(), atom2.index(),
                                     atom3.index());
      }
    } else if (m_type == PropertyType::TorsionType) {
      if (m_model != nullptr) {
        auto torsion = m_model->getTorsion(rowNum);
        auto atom1 = m_molecule->atom(std::get<0>(torsion));
        auto atom2 = m_molecule->atom(std::get<1>(torsion));
        auto atom3 = m_molecule->atom(std::get<2>(torsion));
        auto atom4 = m_molecule->atom(std::get<3>(torsion));
        m_molecule->removeConstraint(atom1.index(), atom2.index(),
                                     atom3.index(), atom4.index());
      }
    }
  }
}

void PropertyView::freezeAtom()
{
  setFrozen(true);
}

void PropertyView::unfreezeAtom()
{
  setFrozen(false);
}

void PropertyView::setFrozen(bool freeze)
{
  // get the selected rows (if any)
  QModelIndexList selectedRows = selectionModel()->selectedRows();

  // if nothing is selected, we're done
  if (selectedRows.isEmpty())
    return;

  if (m_molecule == nullptr)
    return;

  // loop through the selected rows
  for (const auto& index : selectedRows) {
    if (!index.isValid())
      continue;

    // get the row number
    bool ok;
    int rowNum = model()
                   ->headerData(index.row(), Qt::Vertical)
                   .toString()
                   .split(" ")
                   .last()
                   .toLong(&ok) -
                 1;
    if (!ok)
      continue;

    m_molecule->setFrozenAtom(rowNum, freeze);
  }

  m_molecule->emitChanged(Molecule::Atoms);
}

void PropertyView::freezeX()
{
  freezeAxis(0);
}

void PropertyView::freezeY()
{
  freezeAxis(1);
}

void PropertyView::freezeZ()
{
  freezeAxis(2);
}

void PropertyView::freezeAxis(int axis)
{
  // get the selected rows (if any)
  QModelIndexList selectedRows = selectionModel()->selectedRows();

  // if nothing is selected, we're done
  if (selectedRows.isEmpty())
    return;

  if (m_molecule == nullptr)
    return;

  // loop through the selected rows
  for (const auto& index : selectedRows) {
    if (!index.isValid())
      continue;

    // get the row number
    bool ok;
    int rowNum = model()
                   ->headerData(index.row(), Qt::Vertical)
                   .toString()
                   .split(" ")
                   .last()
                   .toLong(&ok) -
                 1;
    if (!ok)
      continue;

    m_molecule->setFrozenAtomAxis(rowNum, axis, true);
  }

  m_molecule->emitChanged(Molecule::Atoms);
}

void PropertyView::openExportDialogBox()
{
  // Create a file dialog for selecting the export location and file name
  QString filePath =
    QFileDialog::getSaveFileName(this, tr("Export CSV"), QDir::homePath(),
                                 tr("CSV Files (*.csv);;All Files (*)"));

  if (filePath.isEmpty()) {
    // User canceled the dialog or didn't provide a file name
    return;
  }

  // Open the file for writing
  QFile file(filePath);
  if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
    // Handle error opening the file
    QMessageBox::critical(this, tr("Error"),
                          tr("Could not open the file for writing."));
    return;
  }

  // Create a QTextStream to write to the file
  QTextStream stream(&file);

  // Write the header row with column names
  for (int col = 0; col < model()->columnCount(); ++col) {
    stream << model()->headerData(col, Qt::Horizontal).toString();
    if (col < model()->columnCount() - 1) {
      stream << ",";
    }
  }
  stream << "\n";

  // Write the data rows
  for (int row = 0; row < model()->rowCount(); ++row) {
    for (int col = 0; col < model()->columnCount(); ++col) {
      stream << model()->index(row, col).data().toString();
      if (col < model()->columnCount() - 1) {
        stream << ",";
      }
    }
    stream << "\n";
  }

  // Close the file
  file.close();

  if (file.error() != QFile::NoError) {
    // Handle error closing the file
    QMessageBox::critical(this, tr("Error"), tr("Error writing to the file."));
  }
}

void PropertyView::contextMenuEvent(QContextMenuEvent* event)
{
  QMenu menu(this);
  QAction* copyAction = menu.addAction(tr("Copy"));
  menu.addAction(copyAction);
  connect(copyAction, &QAction::triggered, this,
          &PropertyView::copySelectedRowsToClipboard);

  QAction* exportAction = menu.addAction(tr("Export…"));
  menu.addAction(exportAction);
  connect(exportAction, &QAction::triggered, this,
          &PropertyView::openExportDialogBox);

  if (m_type == PropertyType::AtomType) {
    // freeze atom
    QAction* freezeAtomAction = menu.addAction(tr("Freeze Atom"));
    menu.addAction(freezeAtomAction);
    connect(freezeAtomAction, &QAction::triggered, this,
            &PropertyView::freezeAtom);
    QAction* freezeX = menu.addAction(tr("Freeze X"));
    menu.addAction(freezeX);
    connect(freezeX, &QAction::triggered, this, &PropertyView::freezeX);
    QAction* freezeY = menu.addAction(tr("Freeze Y"));
    menu.addAction(freezeY);
    connect(freezeY, &QAction::triggered, this, &PropertyView::freezeY);
    QAction* freezeZ = menu.addAction(tr("Freeze Z"));
    menu.addAction(freezeZ);
    connect(freezeZ, &QAction::triggered, this, &PropertyView::freezeZ);
    QAction* unfreezeAtomAction = menu.addAction(tr("Unfreeze Atom"));
    menu.addAction(unfreezeAtomAction);
    connect(unfreezeAtomAction, &QAction::triggered, this,
            &PropertyView::unfreezeAtom);
  } else {
    // bond angle & torsion are similar
    QString name;
    if (m_type == PropertyType::BondType)
      name = tr("Constrain Bond");
    else if (m_type == PropertyType::AngleType)
      name = tr("Constrain Angle");
    else if (m_type == PropertyType::TorsionType)
      name = tr("Constrain Torsion");

    QAction* constrainAction = menu.addAction(name);
    menu.addAction(constrainAction);
    connect(constrainAction, &QAction::triggered, this,
            &PropertyView::constrainSelectedRows);

    QAction* unconstrainAction = menu.addAction(tr("Remove Constraint"));
    menu.addAction(unconstrainAction);
    connect(unconstrainAction, &QAction::triggered, this,
            &PropertyView::unconstrainSelectedRows);
  }

  menu.exec(event->globalPos());
}

} // end namespace Avogadro
