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

#include <QtWidgets/QDialog>

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
  SurfaceDialog(QWidget *parent = 0, Qt::WindowFlags f = 0);
  ~SurfaceDialog();

  void setNumberOfElectrons(int numberOfElectrons, int numberOfMOs);

public slots:
  void setCalculationEnabled(bool isEnabled);

protected slots:
  void surfaceComboChanged(int n);
  void resolutionComboChanged(int n);
  void calculateClicked();

signals:
  void calculateMO(int molecularOrbital, float isoValue, float stepSize);
  void calculateElectronDensity(float isoValue, float stepSize);

private:
  Ui::SurfaceDialog *m_ui;
};

} // End namespace QtPlugins
} // End namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SURFACEDIALOG_H
