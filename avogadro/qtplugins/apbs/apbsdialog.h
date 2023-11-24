/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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
