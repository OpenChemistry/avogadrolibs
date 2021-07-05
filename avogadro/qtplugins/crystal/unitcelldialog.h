/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_UNITCELLDIALOG_H
#define AVOGADRO_QTPLUGINS_UNITCELLDIALOG_H

#include <QtWidgets/QDialog>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/unitcell.h>

class QPlainTextEdit;

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class UnitCellDialog;
}

/**
 * @brief The UnitCellDialog class provides a dialog for editing a molecule's
 * unit cell.
 */
class UnitCellDialog : public QDialog
{
  Q_OBJECT

public:
  enum Mode
  {
    Clean,
    Invalid,
    Parameters,
    CellMatrix,
    FractionalMatrix
  };

  explicit UnitCellDialog(QWidget* parent = nullptr);
  ~UnitCellDialog() override;

  void setMolecule(QtGui::Molecule* molecule);

public slots:
  void moleculeChanged(unsigned int changes);

  void parametersEdited();
  void cellMatrixEdited();
  void fractionalMatrixEdited();

  void apply();
  void revert();

private:
  bool isCrystal() const;

  void setMode(Mode m);

  void enableParameters(bool e);
  void enableCellMatrix(bool e);
  void enableFractionalMatrix(bool e);
  void enableApply(bool e);
  void enableRevert(bool e);

  void blockParametersSignals(bool e);
  void blockCellMatrixSignals(bool e);
  void blockFractionalMatrixSignals(bool e);

  // m_tempCell --> ui
  void revertParameters();
  void revertCellMatrix();
  void revertFractionalMatrix();

  // ui --> m_tempCell
  void updateParameters();
  void updateCellMatrix();
  void updateFractionalMatrix();

  bool validateCellMatrix();
  bool validateFractionalMatrix();

  static void initializeMatrixEditor(QPlainTextEdit* edit);
  static bool validateMatrixEditor(QPlainTextEdit* edit);
  static QString matrixToString(const Matrix3& mat);
  static Matrix3 stringToMatrix(const QString& str);

private:
  Ui::UnitCellDialog* m_ui;
  QtGui::Molecule* m_molecule;
  Core::UnitCell m_tempCell;
  Mode m_mode;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_UNITCELLDIALOG_H
