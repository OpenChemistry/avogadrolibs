/**********************************************************************
  InputDialog - Base class for all QC input dialogs

  Copyright (C) 2010 Konstantin Tokarev

  This file is part of the Avogadro molecular editor project.
  For more information, see <http://avogadro.openmolecules.net/>

  Avogadro is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  Avogadro is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
  02110-1301, USA.
 **********************************************************************/

#ifndef INPUTDIALOG_H
#define INPUTDIALOG_H

//------  OLD INCLUDES IN AVOGADRO2 --------
//#include <avogadro/molecule.h>
//--- END OF OLD INCLUDES IN AVOGADRO2 -----
//------  NEW INCLUDES IN AVOGADRO2 --------
#include <avogadro/qtgui/molecule.h>
//--- END OF NEW INCLUDES IN AVOGADRO2 -----

#include "simuneantinput.h"

#include <QtCore/QSettings>
#include <QDialog>

namespace Avogadro{
namespace QtPlugins {
  class InputDialog : public QDialog
  {
  Q_OBJECT
  public:
    //explicit InputDialog(QWidget *parent = 0, Qt::WindowFlags f = 0 );
    explicit InputDialog(QWidget *parent_ = 0, Qt::WindowFlags f = 0 );
    virtual ~InputDialog();

    // TODO: other enums also must be shared
    enum coordType{CARTESIAN, ZMATRIX, ZMATRIX_COMPACT};

    virtual void setMolecule(QtGui::Molecule *molecule);

    /**
     * Save the settings for this extension.
     * @param settings Settings variable to write settings to.
     */
    virtual void writeSettings(QSettings &settings) const = 0;

    /**
     * Read the settings for this extension.
     * @param settings Settings variable to read settings from.
     */
    virtual void readSettings(QSettings &settings) = 0;
    
  Q_SIGNALS:
    void readOutput(const QString outputFileName);

  public Q_SLOTS:
    virtual void updatePreviewText() = 0;

  protected Q_SLOTS:
   // virtual void defaultsClicked() = 0;
    virtual void resetClicked() = 0;
    virtual void generateClicked() = 0;

  protected:
    QString saveInputFile(QString inputDeck, QString fileType, QString ext);
      
    QtGui::Molecule* m_molecule;
    QString m_title;
    int m_multiplicity;
    int m_charge;
    //QString m_fileName;
    QString m_savePath;
  };
} // end namespace QtPlugins
} // end namespace Avogadro

#endif
