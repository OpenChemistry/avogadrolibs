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

#ifndef AVOGADRO_QTPLUGINS_SUPERCELLDIALOG_H
#define AVOGADRO_QTPLUGINS_SUPERCELLDIALOG_H


#include <QtWidgets/QDialog>

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class SuperCellDialog;
}

class SuperCellDialog : public QDialog
{
  Q_OBJECT

  public:
    explicit SuperCellDialog( QWidget *parent = 0 );
    ~SuperCellDialog() AVO_OVERRIDE;

    void setMolecule(QtGui::Molecule *molecule);

    int aCells();
    int bCells();
    int cCells();

    void aCells(int a);
    void bCells(int b);
    void cCells(int c);

  public slots:
    void valueChanged(int value);

    void fillCellClicked();

  signals:
    void cellDisplayChanged(int a, int b, int c);

  private:
    Ui::SuperCellDialog *m_ui;
    QtGui::Molecule *m_molecule;

    int m_aCells;
    int m_bCells;
    int m_cCells;
  };

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SUPERCELLDIALOG_H
