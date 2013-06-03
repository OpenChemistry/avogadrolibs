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

#ifndef AVOGADRO_QTGUI_INPUTGENERATORWIDGET_H
#define AVOGADRO_QTGUI_INPUTGENERATORWIDGET_H

#include <QtGui/QWidget>

#include <avogadro/qtgui/avogadroqtguiexport.h>
#include <avogadro/qtgui/inputgenerator.h>

#include <avogadro/core/avogadrocore.h>

#include <qjsonobject.h>

class QJsonValue;
class QTextEdit;
class QWidget;

namespace MoleQueue {
class Client;
}

namespace Avogadro {
namespace QtGui {
class Molecule;

namespace Ui {
class InputGeneratorWidget;
}

/**
 * @class InputGeneratorWidget inputgeneratorwidget.h
 * <avogadro/qtgui/inputgeneratorwidget.h>
 * @brief The InputGeneratorWidget class provides a user interface for
 * configuring, saving, editing, and running input files produced by
 * InputGenerator scripts.
 * @sa InputGenerator InputGeneratorDialog
 */
class AVOGADROQTGUI_EXPORT InputGeneratorWidget : public QWidget
{
  Q_OBJECT

public:
  /**
   * Construct a widget that dynamically generates a GUI to configure the
   * InputGenerator script specified by scriptFilePath.
   */
  explicit InputGeneratorWidget(QWidget *parent_ = 0);
  ~InputGeneratorWidget() AVO_OVERRIDE;

  /**
   * Use the input generator script pointed to by scriptFilePath.
   * @param scriptFilePath Absolute path to generator script.
   */
  void setInputGeneratorScript(const QString &scriptFilePath);

  /**
   * Set the molecule used in the simulation.
   */
  void setMolecule(QtGui::Molecule *mol);

  /**
   * Access to the underlying input generator object. @{
   */
  const InputGenerator &inputGenerator() const { return m_inputGenerator; }

signals:
  /**
   * @brief closeClicked is emitted when the close button is clicked.
   */
  void closeClicked();

protected:
  /**
   * Reimplemented to update preview text. Hidden dialogs will wait until they
   * are reshown to update the text to prevent overwriting any modified buffers.
   */
  void showEvent(QShowEvent *e) AVO_OVERRIDE;

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
   * Query the MoleQueue server (if available) for the list of available queues
   * and programs.
   */
  void refreshPrograms();

  /**
   * Triggered when MoleQueue replies to the request from refreshPrograms().
   * Parse the response from MoleQueue and update the GUI.
   */
  void queueListReceived(const QJsonObject &queueList);

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
  void setWarning(const QString &warn);

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
  void showError(const QString &err);

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
  QString settingsKey(const QString &identifier) const;

  /**
   * Enable/disable the GUI for specifying the input file base name.
   */
  void enableBaseNameGui(bool enable = true);

  /**
   * Write the input file(s) to disk. Prompts user for target location.
   * @{
   */
  void saveSingleFile(const QString &fileName);
  void saveDirectory();
  /**@}*/

  /**
   * Make signal/slot connections.
   * @{
   */
  void connectButtons();
  void connectMoleQueue();
  /**@}*/

  /**
   * Given the name of a user-option in m_options, return the type string.
   * If an error occurs, an empty string will be returned.
   */
  QString lookupOptionType(const QString &name) const;

  /**
   * Used to construct the script-specific GUI.
   * @{
   */
  void updateOptions();
  void buildOptionGui();
  void addOptionRow(const QString &label, const QJsonValue &option);
  QWidget* createOptionWidget(const QJsonValue &option);
  QWidget* createStringListWidget(const QJsonObject &obj);
  QWidget* createStringWidget(const QJsonObject &obj);
  QWidget* createIntegerWidget(const QJsonObject &obj);
  QWidget* createBooleanWidget(const QJsonObject &obj);
  /**@}*/

  /**
   * Set the simulation settings to their default values.
   * @{
   */
  void setOptionDefaults();
  void setOption(const QString &name, const QJsonValue &defaultValue);
  void setStringListOption(const QString &name, const QJsonValue &value);
  void setStringOption(const QString &name, const QJsonValue &value);
  void setIntegerOption(const QString &name, const QJsonValue &value);
  void setBooleanOption(const QString &name, const QJsonValue &value);
  /**@}*/

  /**
   * @brief Search for an option named @a option and convert its value to a
   * string.
   * @param option The name of the option.
   * @param value String to overwrite with option value.
   * @return True if value is overwritten, false if the option is not found or
   * cannot be converted to a string.
   */
  bool optionString(const QString &option, QString &value) const;

  /**
   * Collect all of the user-specified options into a JSON object, to be sent
   * to the generator script.
   */
  QJsonObject collectOptions() const;

  /**
   * Collect all settings (options that are not dynamically generated from the
   * input generator script) into a JSON object.
   */
  QJsonObject collectSettings() const;

  /**
   * Apply the options in the passed QJsonObject to the GUI. Any widgets changed
   * by this method will have their signals blocked while modifying their
   * values.
   */
  void applyOptions(const QJsonObject &opts);

  /**
   * Update the autogenerated job title in the GUI.
   */
  QString generateJobTitle() const;

  Ui::InputGeneratorWidget *m_ui;
  QtGui::Molecule *m_molecule;
  MoleQueue::Client *m_client;
  QJsonObject m_options;
  QJsonObject m_optionCache; // For reverting changes
  bool m_updatePending;
  QList<QTextEdit*> m_dirtyTextEdits;
  QtGui::InputGenerator m_inputGenerator;

  QMap<QString, QWidget*> m_widgets;
  QMap<QString, QTextEdit*> m_textEdits;
};


} // namespace QtGui
} // namespace Avogadro
#endif // AVOGADRO_QTGUI_INPUTGENERATORWIDGET_H
