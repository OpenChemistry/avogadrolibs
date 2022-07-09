/******************************************************************************
  This source file is part of the MoleQueue project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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
