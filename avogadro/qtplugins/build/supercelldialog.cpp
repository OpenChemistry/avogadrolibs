/**********************************************************************
  SuperCellDialog - Dialog for building crystallographic super cells

  Copyright (C) 2009 Marcus D. Hanwell

  This file is part of the Avogadro molecular editor project.
  For more information, see <http://avogadro.cc/>

  This library is free software; you can redistribute it and/or modify
  it under the terms of the GNU Library General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 ***********************************************************************/

#include "supercelldialog.h"
#include "ui_supercelldialog.h"

#include <avogadro/qtgui/molecule.h>

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/unitcell.h>

using Avogadro::Core::UnitCell;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

SuperCellDialog::SuperCellDialog(QWidget *p) :
  QDialog(p),
  m_ui(new Ui::SuperCellDialog),
  m_aCells(0), m_bCells(0), m_cCells(0),
  m_molecule(NULL)
{
  m_ui->setupUi(this);
  reject();

  connect(m_ui->generateCell, SIGNAL(clicked()), this, SLOT(fillCellClicked()));

  connect(m_ui->aCellSpinBox, SIGNAL(valueChanged(int)), this, SLOT(valueChanged(int)));
  connect(m_ui->bCellSpinBox, SIGNAL(valueChanged(int)), this, SLOT(valueChanged(int)));
  connect(m_ui->cCellSpinBox, SIGNAL(valueChanged(int)), this, SLOT(valueChanged(int)));
}

SuperCellDialog::~SuperCellDialog()
{
}

void SuperCellDialog::setMolecule(QtGui::Molecule *molecule)
{
  if (molecule != m_molecule) {
    if (m_molecule)
      m_molecule->disconnect(this);

    m_molecule = molecule;
  }
}


void SuperCellDialog::valueChanged(int)
{
  m_aCells = m_ui->aCellSpinBox->value();
  m_bCells = m_ui->bCellSpinBox->value();
  m_cCells = m_ui->cCellSpinBox->value();

  emit(cellDisplayChanged(m_aCells, m_bCells, m_cCells));
}

int SuperCellDialog::aCells()
{
  return m_aCells;
}

void SuperCellDialog::aCells(int a)
{
  m_aCells = a;
  m_ui->aCellSpinBox->setValue(m_aCells);
}

int SuperCellDialog::bCells()
{
  return m_bCells;
}

void SuperCellDialog::bCells(int b)
{
  m_bCells = b;
  m_ui->bCellSpinBox->setValue(m_bCells);
}

int SuperCellDialog::cCells()
{
  return m_cCells;
}

void SuperCellDialog::cCells(int c)
{
  m_cCells = c;
  m_ui->cCellSpinBox->setValue(m_cCells);
}

void SuperCellDialog::fillCellClicked()
{
  Molecule::MoleculeChanges changes = Molecule::UnitCell | Molecule::Modified;
  Core::CrystalTools::buildSuperCell(*m_molecule,m_aCells,m_bCells,m_cCells);
  m_molecule->emitChanged(changes);
}


} // namespace QtPlugins
} // namespace Avogadro
