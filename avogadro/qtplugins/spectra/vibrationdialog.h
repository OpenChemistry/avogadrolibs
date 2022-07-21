/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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
