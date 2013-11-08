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

#ifndef AVOGADRO_QTGUI_INPUTGENERATORDIALOG_H
#define AVOGADRO_QTGUI_INPUTGENERATORDIALOG_H

#include <QtGui/QDialog>

#include <avogadro/core/avogadrocore.h>

#include <avogadro/qtgui/avogadroqtguiexport.h>
#include <avogadro/qtgui/inputgeneratorwidget.h>

#include <QtCore/QSharedPointer>

namespace Avogadro {
namespace QtGui {
class Molecule;

namespace Ui {
class InputGeneratorDialog;
}

/**
 * @class InputGeneratorDialog inputgeneratordialog.h
 * <avogadro/qtgui/inputgeneratordialog.h>
 * @brief The InputGeneratorDialog class provides a thin wrapper around
 * InputGeneratorWidget for standalone use.
 * @sa InputGenerator InputGeneratorWidget
 */
class AVOGADROQTGUI_EXPORT InputGeneratorDialog : public QDialog
{
  Q_OBJECT

public:
  class BatchOptions;

  explicit InputGeneratorDialog(QWidget *parent_ = 0);
  explicit InputGeneratorDialog(const QString &scriptFileName,
                                QWidget *parent_ = 0);
  ~InputGeneratorDialog() AVO_OVERRIDE;

  /**
   * Use the input generator script pointed to by scriptFilePath.
   * @param scriptFilePath Absolute path to generator script.
   */
  void setInputGeneratorScript(const QString &scriptFilePath);

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
   * options are collected in the returned BatchOptions object.
   *
   * Errors are handled internally. User cancellation is indicated by this
   * method returning an uninitialized BatchOptions object -- use
   * BatchOptions::isValid to check if the user canceled.
   *
   * The returned BatchOptions object, if valid, is used in subsequent calls to
   * submitNextJobInBatch(), which will submit jobs using the configured options
   * for individual molecules.
   */
  BatchOptions collectBatchOptions();

  /**
   * Using the BatchOptions obtained from a call to collectBatchOptions(),
   * construct and submit a new job that uses the Molecule @a mol as input.
   *
   * Returns false if an error occurs.
   */
  bool submitNextJobInBatch(const QtGui::Molecule &mol,
                            const BatchOptions &options);

public slots:
  /**
   * Set the molecule used in the simulation.
   */
  void setMolecule(QtGui::Molecule *mol);

private:
  Ui::InputGeneratorDialog *ui;
};

/**
 * Object to hold calculation and job options for batch job submissions.
 */
class AVOGADROQTGUI_EXPORT InputGeneratorDialog::BatchOptions
{
public:
  friend class InputGeneratorDialog;
  BatchOptions() : options(NULL) {}
  BatchOptions(const BatchOptions &other) : options(other.options) {}
  BatchOptions& operator=(const BatchOptions &o)
  {
    options = o.options;
    return *this;
  }

  bool isValid() const { return !options.isNull(); }

  friend void swap(BatchOptions &lhs, BatchOptions &rhs)
  {
    using std::swap;
    swap(lhs.options, rhs.options);
  }

protected:
  typedef QSharedPointer<InputGeneratorWidget::BatchOptions> DataType;
  DataType options;
};

} // namespace QtGui
} // namespace Avogadro
#endif // AVOGADRO_QTGUI_INPUTGENERATORDIALOG_H
