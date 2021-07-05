/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_MOLEQUEUE_INPUTGENERATORDIALOG_H
#define AVOGADRO_MOLEQUEUE_INPUTGENERATORDIALOG_H

#include "avogadromolequeueexport.h"
#include "inputgeneratorwidget.h"
#include <QtWidgets/QDialog>
#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtGui {
class Molecule;
}

namespace MoleQueue {
class BatchJob;
namespace Ui {
class InputGeneratorDialog;
}
class InputGeneratorWidget;
/**
 * @class InputGeneratorDialog inputgeneratordialog.h
 * <avogadro/molequeue/inputgeneratordialog.h>
 * @brief The InputGeneratorDialog class provides a thin wrapper around
 * InputGeneratorWidget for standalone use.
 * @sa InputGenerator InputGeneratorWidget
 */
class AVOGADROMOLEQUEUE_EXPORT InputGeneratorDialog : public QDialog
{
  Q_OBJECT

public:
  explicit InputGeneratorDialog(QWidget* parent_ = nullptr);
  explicit InputGeneratorDialog(const QString& scriptFileName,
                                QWidget* parent_ = nullptr);
  ~InputGeneratorDialog() override;

  /**
   * Use the input generator script pointed to by scriptFilePath.
   * @param scriptFilePath Absolute path to generator script.
   */
  void setInputGeneratorScript(const QString& scriptFilePath);

  /**
   * @return A reference to the internal InputGeneratorWidget.
   * @{
   */
  InputGeneratorWidget& widget();
  const InputGeneratorWidget& widget() const;
  /** @} */

  /**
   * Used to configure batch jobs.
   *
   * When performing the same calculation on a number of molecules, this method
   * will ask the user to configure a calculation using the current molecule and
   * input generator settings. After the calculation settings are accepted, a
   * MoleQueueDialog is used to set job options. Both calculation and job
   * options are stored in the supplied BatchJob object.
   *
   * Errors are handled internally. User cancellation is indicated by this
   * method returning false.
   *
   * To submit jobs using the configured options, call BatchJob::submitNextJob
   * for each molecule.
   *
   * Typical usage:
~~~
  BatchJob *batch = ...;
  InputGeneratorDialog dlg(scriptFilePath, windowParent);
  dlg.setMolecule(&refMol); // Representative molecule as placeholder in GUI.
  dlg.configureBatchJob(*batch);
  foreach(mol)
    batch->submitNextJob(mol);
~~~
   */
  bool configureBatchJob(BatchJob& batch);

public slots:
  /**
   * Set the molecule used in the simulation.
   */
  void setMolecule(QtGui::Molecule* mol);

private:
  Ui::InputGeneratorDialog* ui;
};

} // namespace MoleQueue
} // namespace Avogadro

#endif // AVOGADRO_MOLEQUEUE_INPUTGENERATORDIALOG_H
