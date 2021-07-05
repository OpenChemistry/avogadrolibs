/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_VIBRATIONDIALOG_H
#define AVOGADRO_QTPLUGINS_VIBRATIONDIALOG_H

#include <QtWidgets/QDialog>

#include <avogadro/qtgui/molecule.h>

#include <QtCore/QModelIndex>

namespace Ui {
class VibrationDialog;
}

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The VibrationDialog presents vibrational modes.
 */

class VibrationDialog : public QDialog
{
  Q_OBJECT

public:
  VibrationDialog(QWidget* parent = nullptr, Qt::WindowFlags f = 0);
  ~VibrationDialog() override;

  void setMolecule(QtGui::Molecule* molecule);
  int currentMode() const;

protected slots:
  void selectRow(QModelIndex);

signals:
  void modeChanged(int mode);
  void amplitudeChanged(int amplitude);
  void startAnimation();
  void stopAnimation();

private:
  Ui::VibrationDialog* m_ui;
};

} // End namespace QtPlugins
} // End namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_VibrationDialog_H
