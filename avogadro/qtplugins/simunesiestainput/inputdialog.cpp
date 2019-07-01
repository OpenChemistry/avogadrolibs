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

#include "inputdialog.h"
#include "simunesiestainput.h"
#include <QtCore/QString>
#include <QFileDialog>
#include <QtCore/QDebug>

namespace Avogadro {
namespace QtPlugins {
  //InputDialog::InputDialog(QWidget *parent, Qt::WindowFlags f) :
  InputDialog::InputDialog(QWidget *parent_, Qt::WindowFlags f) :
                QDialog(parent, f), m_molecule(0), m_title("Title"),
                m_multiplicity(1), m_charge(0), m_savePath("")
  {}

  InputDialog::~InputDialog()
  {}

  void InputDialog::setMolecule(QtGui::Molecule *molecule)
  {
    m_molecule = molecule;
  }

  QString InputDialog::saveInputFile(QString inputDeck, QString fileType, QString ext)
  {
    // Try to set default save path for dialog using the next sequence:
    //  1) directory of current file (if any);
    //  2) directory where previous deck was saved;
    //  3) $HOME

    QFileInfo defaultFile(m_molecule->fileName()); // REPLACED BELOW TO WORK IN AVOGADRO2
    //QFileInfo defaultFile(m_outputFileName);

    QString defaultPath = defaultFile.canonicalPath();
    if(m_savePath == "") {
      if (defaultPath.isEmpty())
        defaultPath = QDir::homePath();
    } else {
      defaultPath = m_savePath;
    }

    QString defaultFileName = defaultPath + '/' + defaultFile.baseName() + "." + ext;
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Input Deck"),
        defaultFileName, fileType + " (*." + ext + ")");

    if(fileName == "")
      return fileName;

    QFile file(fileName);
    if(!file.open(QIODevice::WriteOnly | QIODevice::Text)) return QString();

    file.write(inputDeck.toLocal8Bit()); // prevent troubles in Windows
    file.close(); // flush buffer!
    m_savePath = QFileInfo(file).absolutePath();
    return fileName;
  }

} // end namespace QtPlugins
} // end namespace Avogadro

