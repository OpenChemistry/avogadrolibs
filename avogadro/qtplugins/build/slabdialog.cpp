/**********************************************************************
  SlabDialog - Dialog for building crystallographic slab cells

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

#include "slabdialog.h"
#include "ui_slabdialog.h"

#include <avogadro/qtgui/molecule.h>

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include <QtCore/QString>
#include <QDebug>

using Avogadro::Core::UnitCell;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

SlabDialog::SlabDialog(QWidget *p) :
  QDialog(p),
  m_ui(new Ui::SlabDialog),
  m_i(0), m_h(1), m_k(1), m_l(1),
  m_x(0.0), m_y(0.0), m_z(0.0),
  m_lengthUnit(Angstrom),
  m_molecule(NULL)
{
  m_ui->setupUi(this);
  // Hide the "i" Miller index if not a hexagonal unit cell
  m_ui->spin_mi_i->hide();

  // Hide the Miller index warning label by default
  m_ui->warningLabel->hide();
  //readSettings(); // hides or shows the warning if needed

  // Add the suffix to the xyz distances
  updateLengthUnit();
  //connect(m_ext, SIGNAL(lengthUnitChanged(LengthUnit)),
   //   this, SLOT(updateLengthUnit()));

  // Update the Miller indices
  m_ui->spin_mi_h->setValue(1);
  m_ui->spin_mi_k->setValue(1);
  m_ui->spin_mi_l->setValue(1);
  connect(m_ui->spin_mi_h, SIGNAL(valueChanged(int)),
      this, SLOT(updateMillerIndices()));
  connect(m_ui->spin_mi_k, SIGNAL(valueChanged(int)),
      this, SLOT(updateMillerIndices()));
  connect(m_ui->spin_mi_l, SIGNAL(valueChanged(int)),
      this, SLOT(updateMillerIndices()));
  // No need to update "i" index -- it's locked and updated from h & k

  // If the x/y cutoffs change, we'll need to append a suffix for the unit
  connect(m_ui->xWidthUnits, SIGNAL(currentIndexChanged(int)),
      this, SLOT(updateLengthUnit()));
  connect(m_ui->yWidthUnits, SIGNAL(currentIndexChanged(int)),
      this, SLOT(updateLengthUnit()));

  connect(m_ui->buildButton, SIGNAL(clicked(bool)),
      this, SLOT(buildSlab()));

  updateMillerIndices();
}

SlabDialog::~SlabDialog()
{
}

void SlabDialog::setMolecule(QtGui::Molecule *molecule)
{
  if (molecule != m_molecule) {
    if (m_molecule)
      m_molecule->disconnect(this);

    m_molecule = molecule;
  }
}

//  Conversion factor (storage * [factor] = display)
double SlabDialog::lengthConversionFactor() const
{
  // Storage is in angstrom, so convert appropriately.
  switch (lengthUnit()) {
    default:
    case Angstrom:  return 1.0;
    case Bohr:      return 1.8897162;
    case Nanometer: return 1e-1;
    case Picometer: return 1e2;
  }
}

void SlabDialog::updateLengthUnit()
{

  // Called when the user changes the length unit
  QString lengthSuffix;
  switch (lengthUnit()) {
    case Angstrom:
      lengthSuffix = CE_ANGSTROM;
      break;
    case Bohr:
      lengthSuffix = " a" + CE_SUB_ZERO;
      break;
    case Nanometer:
      lengthSuffix = " nm";
      break;
    case Picometer:
      lengthSuffix = " pm";
      break;
    default:
      lengthSuffix = "";
      break;
  }

  m_ui->xWidthUnits->setItemText(0, lengthSuffix);
  m_ui->yWidthUnits->setItemText(0, lengthSuffix);

  if (m_ui->xWidthUnits->currentIndex() == 0)
    m_ui->spin_slab_x->setSuffix(lengthSuffix);
  else
    m_ui->spin_slab_x->setSuffix("");

  if (m_ui->yWidthUnits->currentIndex() == 0)
    m_ui->spin_slab_y->setSuffix(lengthSuffix);
  else
    m_ui->spin_slab_y->setSuffix("");

  m_ui->spin_slab_z->setSuffix(lengthSuffix);

}


void SlabDialog::updateMillerIndices()
{
  // Get miller indices:
  const Vector3 millerIndices
    (static_cast<double>(m_ui->spin_mi_h->value()),
     static_cast<double>(m_ui->spin_mi_k->value()),
     static_cast<double>(m_ui->spin_mi_l->value()));

  // Check that the indices aren't 0,0,0
  if (millerIndices.norm() < 0.5) {
    m_ui->warningLabel->show();
    m_ui->buildButton->setEnabled(false);
    return;
  }

  //if hexagonal
  // i = -h - k
  // http://en.wikipedia.org/wiki/Miller_index#Case_of_hexagonal_and_rhombohedral_structures
  //ui->spin_mi_i->setValue(-ui.spin_mi_h->value() - ui.spin_mi_k->value());
  //otherwise ui.spin_mi_i->hide();
  m_i=m_ui->spin_mi_i->value();
  m_h=m_ui->spin_mi_h->value();
  m_k=m_ui->spin_mi_k->value();
  m_l=m_ui->spin_mi_l->value();

  m_x=m_ui->spin_slab_x->value();
  m_y=m_ui->spin_slab_y->value();
  m_z=m_ui->spin_slab_z->value();

  // In case warning was visible:
  m_ui->warningLabel->hide();
  m_ui->buildButton->setEnabled(true);
  //writeSettings();

  //emit(cellDisplayChanged(m_aCells, m_bCells, m_cCells));
}

void SlabDialog::buildSlab()
{
  updateMillerIndices();
  std::vector<int> m_indices;
  m_indices.push_back(m_h);
  m_indices.push_back(m_k);
  m_indices.push_back(m_l);

  Vector3 m_cutoff;
  m_cutoff << m_x , m_y , m_z;

  Molecule::MoleculeChanges changes = Molecule::UnitCell | Molecule::Modified;
  Core::CrystalTools::buildSlab(*m_molecule,m_indices,m_cutoff);
  m_molecule->emitChanged(Molecule::UnitCell | Molecule::Modified | Molecule::Atoms);
}




} // namespace QtPlugins
} // namespace Avogadro
