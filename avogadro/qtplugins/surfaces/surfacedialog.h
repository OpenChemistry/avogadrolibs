/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SURFACEDIALOG_H
#define AVOGADRO_QTPLUGINS_SURFACEDIALOG_H

#include <QtCore/QStringList>
#include <QtWidgets/QDialog>

#include "surfaces.h"
// for the enum

namespace Ui {
class SurfaceDialog;
}

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The SurfaceDialog presents various properties that have been read in
 * from a quantum output file and provides interface to initiate calculations.
 */

class SurfaceDialog : public QDialog
{
  Q_OBJECT

public:
  SurfaceDialog(QWidget* parent = nullptr, Qt::WindowFlags f = 0);
  ~SurfaceDialog() override;

  void setupBasis(int numElectrons, int numMOs, bool beta);
  void setupCubes(QStringList cubeNames);
  void setupSteps(int stepCount);
  void reenableCalculateButton();
  void enableRecord();

  Surfaces::Type surfaceType();

  /**
   * This holds the value of the molecular orbital at present.
   */
  int surfaceIndex();

  /**
   * Only relevant for electronic structure, was the beta orbital selected?
   */
  bool beta();

  float isosurfaceValue();

  int smoothingPassesValue();

  float resolution();

  bool automaticResolution();

  int step();
  void setStep(int step);

public slots:

protected slots:
  void surfaceComboChanged(int n);
  void resolutionComboChanged(int n);
  void smoothingComboChanged(int n);
  void calculateClicked();
  void record();

signals:
  void stepChanged(int n);
  void calculateClickedSignal();
  void recordClicked();

private:
  Ui::SurfaceDialog* m_ui;
  bool m_automaticResolution;
};

} // End namespace QtPlugins
} // End namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SURFACEDIALOG_H
