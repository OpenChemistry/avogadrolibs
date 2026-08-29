/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_VIBRATIONDIALOG_H
#define AVOGADRO_QTPLUGINS_VIBRATIONDIALOG_H

#include <QtWidgets/QDialog>

#include <avogadro/qtgui/molecule.h>

#include <QtCore/QList>
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
  explicit VibrationDialog(QWidget* parent = nullptr,
                           Qt::WindowFlags f = Qt::WindowFlags());
  ~VibrationDialog() override;

  void setMolecule(QtGui::Molecule* molecule);
  int currentMode() const;

  /**
   * @return The rows selected in the mode table, in increasing order. Empty
   * when nothing is selected.
   */
  QList<int> selectedModes() const;

  /**
   * Put the animation button back into its "stopped" state, for when the
   * animation is stopped by something other than the button itself (such as
   * the active conformer changing).
   */
  void resetAnimationButton();

protected slots:
  void selectRow(QModelIndex);
  void changeAnimation();
  void showTableContextMenu(const QPoint& point);
  void requestDisplacedCoordinates();

signals:
  void modeChanged(int mode);
  /**
   * The user asked for new coordinate sets displaced along @p modes, summed
   * and scaled by @p scale. @p structures is how many geometries to generate.
   */
  void generateDisplacedCoordinates(const QList<int>& modes, double scale,
                                    int structures);
  void amplitudeChanged(int amplitude);
  void startAnimation();
  void stopAnimation();

private:
  /** Human-readable list of @p modes, for the displacement dialog. */
  QString modeSummary(const QList<int>& modes) const;

  Ui::VibrationDialog* m_ui;
};

} // End namespace QtPlugins
} // End namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_VibrationDialog_H
