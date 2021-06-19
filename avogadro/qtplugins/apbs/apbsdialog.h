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

#ifndef AVOGADRO_QTPLUGINS_APBS_APBSDIALOG_H
#define AVOGADRO_QTPLUGINS_APBS_APBSDIALOG_H

#include <avogadro/core/cube.h>

#include <QDialog>

namespace Ui {
class ApbsDialog;
}

namespace Avogadro {
namespace QtGui {
class Molecule;
}
namespace MoleQueue {
class InputGenerator;
}

namespace QtPlugins {

/**
 * @brief Dialog for running APBS.
 */
class ApbsDialog : public QDialog
{
  Q_OBJECT

public:
  /**
   * Constructor for ApbsDialog.
   */
  ApbsDialog(QWidget* parent_ = nullptr);

  /**
   * Destructor for ApbsDialog.
   */
  ~ApbsDialog() override;

  void setMolecule(QtGui::Molecule* molecule);

  /**
   * Returns the file name for the input .pqr file.
   */
  QString pqrFileName() const;

  /**
   * Returns the file name for the output .dx file.
   */
  QString cubeFileName() const;

private slots:
  void openPdbFile();
  void openPqrFile();
  void runApbs();
  void runPdb2Pqr();
  void saveInputFile();
  void saveInputFile(const QString& fileName);

private:
  void updatePreviewTextImmediately();

private:
  Ui::ApbsDialog* m_ui;
  QString m_generatedPqrFileName;
  QtGui::Molecule* m_molecule;
  MoleQueue::InputGenerator* m_inputGenerator;
  QString m_cubeFileName;
  bool m_loadStructureFile;
  bool m_loadCubeFile;
};
}
}

#endif // AVOGADRO_QTPLUGINS_APBS_APBSDIALOG_H
