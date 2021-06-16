/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2009 Marcus D. Hanwell
  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

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

  float resolution();

  int step();
  void setStep(int step);

public slots:

protected slots:
  void surfaceComboChanged(int n);
  void resolutionComboChanged(int n);
  void calculateClicked();
  void record();

signals:
  void stepChanged(int n);
  void calculateClickedSignal();
  void recordClicked();

private:
  Ui::SurfaceDialog* m_ui;
};

} // End namespace QtPlugins
} // End namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SURFACEDIALOG_H
