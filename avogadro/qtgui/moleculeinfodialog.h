/******************************************************************************

  This source file is part of the MoleQueue project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTGUI_MOLECULEINFODIALOG_H
#define AVOGADRO_QTGUI_MOLECULEINFODIALOG_H

#include "avogadroqtguiexport.h"
#include <QtWidgets/QDialog>

namespace Avogadro {
namespace QtGui {

class Molecule;

namespace Ui {
class MoleculeInfoDialog;
}

/**
 * @brief The MoleculeInfoDialog class provides a dialog with options for
 * adjusting the volume of a Molecule's UnitCell.
 */
class AVOGADROQTGUI_EXPORT MoleculeInfoDialog : public QDialog
{
  Q_OBJECT

public:
  explicit MoleculeInfoDialog(QWidget* parent = 0);
  ~MoleculeInfoDialog();

  int atomCount() const;
  bool hasBoxCoordinates() const;

  static bool resolve(QWidget* p, Molecule& mol, QString fname);

private:
  Ui::MoleculeInfoDialog* m_ui;
  double m_currentVolume;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_MOLECULEINFODIALOG_H
