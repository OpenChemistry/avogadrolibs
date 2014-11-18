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

#ifndef AVOGADRO_QTPLUGINS_SLABDIALOG_H
#define AVOGADRO_QTPLUGINS_SLABDIALOG_H


#include <QtWidgets/QDialog>
#include <QtCore/QString>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/vector.h>


namespace Avogadro {
    enum LengthUnit {
      Angstrom = 0,
      Bohr,
      Nanometer,
      Picometer
    };

    const unsigned short CE_ANGSTROM_UTF16 = 0x212B;
    const QString CE_ANGSTROM =
      QString::fromUtf16(&CE_ANGSTROM_UTF16, 1);

    const unsigned short CE_SUB_ZERO_UTF16 = 0x2080;
    const QString CE_SUB_ZERO =
      QString::fromUtf16(&CE_SUB_ZERO_UTF16, 1);

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class SlabDialog;
}

class SlabDialog : public QDialog
{
  Q_OBJECT

  public:
    explicit SlabDialog( QWidget *parent = 0 );
    ~SlabDialog() AVO_OVERRIDE;

    void setMolecule(QtGui::Molecule *molecule);

  public slots:
    // Miller indices changed
    void updateMillerIndices();
    // Do the work!
    void buildSlab();
    // Called by the extension if the user changes the length setting
    // (unlikely)
    void updateLengthUnit();

    LengthUnit lengthUnit() const {return m_lengthUnit;};
    //void valueChanged(int value);

    //void fillCellClicked();

  signals:
    void finished();

  protected:
    void updateSlabCell(bool build = false);

  private:

    Ui::SlabDialog *m_ui;
    QtGui::Molecule *m_molecule;

    double lengthConversionFactor() const;

    LengthUnit m_lengthUnit;

    int m_i;
    int m_h;
    int m_k;
    int m_l;
    double m_x;
    double m_y;
    double m_z;
  };

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SLABDIALOG_H
