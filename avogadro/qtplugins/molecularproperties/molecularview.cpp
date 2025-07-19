/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molecularview.h"

#include <avogadro/qtgui/molecule.h>

#include <QAction>
#include <QApplication>
#include <QtCore/QAbstractTableModel>
#include <QtCore/QDir>
#include <QtCore/QIODevice>
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

MolecularView::MolecularView(QWidget* parent)
  : QTableView(parent), m_molecule(nullptr), m_model(nullptr)
{
  this->setWindowTitle(tr("Molecule Properties"));

  QHeaderView* horizontal = this->horizontalHeader();
  horizontal->setSectionResizeMode(QHeaderView::Interactive);
  QHeaderView* vertical = this->verticalHeader();
  vertical->setSectionResizeMode(QHeaderView::Interactive);

  // You can select everything (e.g., to copy, select all, etc.)
  setCornerButtonEnabled(true);
  setSelectionBehavior(QAbstractItemView::SelectRows);
  setSelectionMode(QAbstractItemView::ExtendedSelection);
  // Alternating row colors
  setAlternatingRowColors(true);
  // Don't allow sorting the table
  setSortingEnabled(false);
}

void MolecularView::selectionChanged(
  [[maybe_unused]] const QItemSelection& selected, const QItemSelection&)
{
}

void MolecularView::setMolecule(Molecule* molecule)
{
  m_molecule = molecule;
}

void MolecularView::hideEvent(QHideEvent*)
{
  if (model()) {
    model()->deleteLater();
  }

  this->deleteLater();
}

void MolecularView::keyPressEvent(QKeyEvent* event)
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

void MolecularView::copySelectedRowsToClipboard()
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

void MolecularView::openExportDialogBox()
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
    stream << model()->headerData(row, Qt::Vertical).toString() << ",";
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

void MolecularView::contextMenuEvent(QContextMenuEvent* event)
{
  QMenu menu(this);
  QAction* copyAction = menu.addAction(tr("Copy"));
  menu.addAction(copyAction);
  connect(copyAction, &QAction::triggered, this,
          &MolecularView::copySelectedRowsToClipboard);

  QAction* exportAction = menu.addAction(tr("Export…"));
  menu.addAction(exportAction);
  connect(exportAction, &QAction::triggered, this,
          &MolecularView::openExportDialogBox);

  menu.exec(event->globalPos());
}

} // end namespace Avogadro
