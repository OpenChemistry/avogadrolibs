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

#ifndef AVOGADRO_QTPLUGINS_VOLUMESCALINGDIALOG_H
#define AVOGADRO_QTPLUGINS_VOLUMESCALINGDIALOG_H

#include <QtWidgets/QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class VolumeScalingDialog;
}

/**
 * @brief The VolumeScalingDialog class provides a dialog with options for
 * adjusting the volume of a Molecule's UnitCell.
 */
class VolumeScalingDialog : public QDialog
{
  Q_OBJECT

public:
  explicit VolumeScalingDialog(QWidget* parent = nullptr);
  ~VolumeScalingDialog() override;

  void setCurrentVolume(double vol);
  double newVolume() const;
  bool transformAtoms() const;

private slots:
  void volumeEdited();
  void factorEdited();

private:
  Ui::VolumeScalingDialog* m_ui;
  double m_currentVolume;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_VOLUMESCALINGDIALOG_H
