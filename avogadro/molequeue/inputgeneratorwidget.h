/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_MOLEQUEUE_INPUTGENERATORWIDGET_H
#define AVOGADRO_MOLEQUEUE_INPUTGENERATORWIDGET_H

#include <QtWidgets/QWidget>

#include "inputgenerator.h"

#include <QtCore/QJsonObject>

class QJsonValue;
class QTextEdit;
class QWidget;

namespace Avogadro {
namespace QtGui {
class Molecule;
}

namespace MoleQueue {
class JobObject;
namespace Ui {
class InputGeneratorWidget;
}
class BatchJob;
/**
 * @class InputGeneratorWidget inputgeneratorwidget.h
 * <avogadro/molequeue/inputgeneratorwidget.h>
 * @brief The InputGeneratorWidget class provides a user interface for
 * configuring, saving, editing, and running input files produced by
 * InputGenerator scripts.
 * @sa InputGenerator InputGeneratorDialog
 *
 * The InputGeneratorWidget creates a GUI to represent the options given by an
 * input generator script, and has some utilities for job submission through
 * MoleQueue.
 *
 * By default, the widget will configure input files for a single molecule,
 * which can be either written to disk or submitted for processing with
 * MoleQueue.
 *
 * By enabling batch mode (setBatchMode()), the current molecule is used to
 * configure a calculation for submission to MoleQueue, and the parameters are
 * saved. These may be used to configure and submit jobs for other molecules.
 */
class AVOGADROMOLEQUEUE_EXPORT InputGeneratorWidget : public QWidget
{
  Q_OBJECT

public:
  /**
   * Construct a widget that dynamically generates a GUI to configure the
   * InputGenerator script specified by scriptFilePath.
   */
  explicit InputGeneratorWidget(QWidget* parent_ = nullptr);
  ~InputGeneratorWidget() override;

  /**
   * Use the input generator script pointed to by scriptFilePath.
   * @param scriptFilePath Absolute path to generator script.
   */
  void setInputGeneratorScript(const QString& scriptFilePath);

  /**
   * Set the molecule used in the simulation.
   */
  void setMolecule(QtGui::Molecule* mol);

  /**
   * Access to the underlying input generator object. @{
   */
  const InputGenerator& inputGenerator() const { return m_inputGenerator; }

  /**
   * @return True if the widget is in batch mode. See the class documentation
   * for details. Default is false.
   */
  bool batchMode() const { return m_batchMode; }

  /**
   * Collect the current calculation parameters and prompt for MoleQueue
   * options. Both option sets are stored in @a batch.
   */
  bool configureBatchJob(BatchJob& batch) const;

public slots:
  /**
   * Enable/disable 'template mode'. See the class documentation for details.
   * Default is off.
   */
  void setBatchMode(bool m);

signals:
  /**
   * @brief closeClicked is emitted when the close button is clicked.
   */
  void closeClicked();

  /**
   * Emitted when the user requests that a job's output be loaded in Avogadro.
   */
  void openJobOutput(const JobObject& job);

protected:
  /**
   * Reimplemented to update preview text. Hidden dialogs will wait until they
   * are reshown to update the text to prevent overwriting any modified buffers.
   */
  void showEvent(QShowEvent* e) override;

private slots:
  /**
   * Update the input files. This method is throttled, and will only call the
   * generator script once every 250 milliseconds.
   */
  void updatePreviewText();

  /**
   * Immediately update the input files, bypassing (and resetting) the throttle
   * mechanism.
   */
  void updatePreviewTextImmediately();

  /**
   * Triggered when the user resets the default values.
   */
  void defaultsClicked();

  /**
   * Triggered when the user requests that the files are written to disk.
   */
  void generateClicked();

  /**
   * Triggered when the user requests that the simulation is submitted to
   * MoleQueue.
   */
  void computeClicked();

  /**
   * Show the user an warning. These are messages returned by the input
   * generator script.
   */
  void setWarning(const QString& warn);

  /**
   * Toggle the visibility of the warning text.
   */
  void toggleWarningText();

  /**
   * Show the warning text.
   */
  void showWarningText();

  /**
   * Hide the warning text.
   */
  void hideWarningText();

  /**
   * Hide the warning widget.
   */
  void resetWarningDisplay();

  /**
   * Show the user an error message. These are errors that have occurred
   * in this extension, not necessarily in the input generator script.
   */
  void showError(const QString& err);

  /**
   * Triggered when an input file's text edit is modified.
   */
  void textEditModified();

  /**
   * Generate a job title automatically.
   */
  void updateTitlePlaceholder();

private:
  /**
   * Generate a QSettings key with the given identifier that is unique to this
   * input generator's display name.
   * @param identifier Setting key, e.g. "outputPath"
   * @return Script-specific key, e.g. "quantumInput/GAMESS/outputPath"
   * @todo Display names are not necessarily unique, but paths are too long.
   * Maybe add a namespace qualifier to the script display names?
   */
  QString settingsKey(const QString& identifier) const;

  /**
   * Write the input file(s) to disk. Prompts user for target location.
   * @{
   */
  void saveSingleFile(const QString& fileName);
  void saveDirectory();
  /**@}*/

  /** Get batch job options from MoleQueueDialog. */
  QJsonObject promptForBatchJobOptions() const;

  /**
   * Make signal/slot connections.
   */
  void connectButtons();

  /**
   * Given the name of a user-option in m_options, return the type string.
   * If an error occurs, an empty string will be returned.
   */
  QString lookupOptionType(const QString& name) const;

  /**
   * Used to construct the script-specific GUI.
   * @{
   */
  void updateOptions();
  void buildOptionGui();
  void addOptionRow(const QString& label, const QJsonValue& option);
  QWidget* createOptionWidget(const QJsonValue& option);
  QWidget* createStringListWidget(const QJsonObject& obj);
  QWidget* createStringWidget(const QJsonObject& obj);
  QWidget* createFilePathWidget(const QJsonObject& obj);
  QWidget* createIntegerWidget(const QJsonObject& obj);
  QWidget* createFloatWidget(const QJsonObject& obj);
  QWidget* createBooleanWidget(const QJsonObject& obj);
  /**@}*/

  /**
   * Set the simulation settings to their default values.
   * @{
   */
  void setOptionDefaults();
  void setOption(const QString& name, const QJsonValue& defaultValue);
  void setStringListOption(const QString& name, const QJsonValue& value);
  void setStringOption(const QString& name, const QJsonValue& value);
  void setFilePathOption(const QString& name, const QJsonValue& value);
  void setIntegerOption(const QString& name, const QJsonValue& value);
  void setBooleanOption(const QString& name, const QJsonValue& value);
  /**@}*/

  /**
   * @brief Search for an option named @a option and convert its value to a
   * string.
   * @param option The name of the option.
   * @param value String to overwrite with option value.
   * @return True if value is overwritten, false if the option is not found or
   * cannot be converted to a string.
   */
  bool optionString(const QString& option, QString& value) const;

  /**
   * Collect all of the user-specified options into a JSON object, to be sent
   * to the generator script.
   */
  QJsonObject collectOptions() const;

  /**
   * Apply the options in the passed QJsonObject to the GUI. Any widgets changed
   * by this method will have their signals blocked while modifying their
   * values.
   */
  void applyOptions(const QJsonObject& opts);

  /**
   * Update the autogenerated job title in the GUI.
   */
  QString generateJobTitle() const;

  Ui::InputGeneratorWidget* m_ui;
  QtGui::Molecule* m_molecule;
  QJsonObject m_options;
  QJsonObject m_optionCache; // For reverting changes
  bool m_updatePending;
  bool m_batchMode;
  QList<QTextEdit*> m_dirtyTextEdits;
  InputGenerator m_inputGenerator;

  QMap<QString, QWidget*> m_widgets;
  QMap<QString, QTextEdit*> m_textEdits;
};

} // namespace MoleQueue
} // namespace Avogadro

#endif // AVOGADRO_MOLEQUEUE_INPUTGENERATORWIDGET_H
