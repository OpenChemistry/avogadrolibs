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

#ifndef AVOGADRO_QTGUI_INTERFACEWIDGET_H
#define AVOGADRO_QTGUI_INTERFACEWIDGET_H

#include "avogadroqtguiexport.h"

#include <QtCore/QJsonObject>
#include <QtCore/QMap>
#include <QtWidgets/QWidget>

#include "interfacescript.h"

class QJsonValue;
class QTextEdit;
class QWidget;

namespace Avogadro {
namespace QtGui {
class Molecule;

/**
 * @class InterfaceWidget interfacewidget.h
 * <avogadro/qtgui/interfacewidget.h>
 * @brief The InterfaceWidget class provides a user interface for
 * running external scripts
 * @sa InterfaceScript
 *
 * The InterfaceWidget creates a GUI to represent the options given by an
 * script, turning JSON from the script into a form and passing the results
 * back to the script via command-line
 */
class AVOGADROQTGUI_EXPORT InterfaceWidget : public QWidget
{
  Q_OBJECT

public:
  /**
   * Construct a widget that dynamically generates a GUI to configure the
   * script specified by scriptFilePath.
   */
  explicit InterfaceWidget(const QString& scriptFilePath,
                           QWidget* parent_ = nullptr);
  ~InterfaceWidget() override;

  /**
   * Use the script pointed to by scriptFilePath.
   * @param scriptFilePath Absolute path to script.
   */
  void setInterfaceScript(const QString& scriptFilePath);

  /**
   * Set the molecule used in the simulation.
   */
  void setMolecule(QtGui::Molecule* mol);

  /**
   * Access to the underlying input generator object.
   */
  const QtGui::InterfaceScript& interfaceScript() const
  {
    return m_interfaceScript;
  }

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

  bool isEmpty() const { return m_empty; }

private slots:
  /**
   * Triggered when the user resets the default values.
   */
  void defaultsClicked();

  /**
   * Show the user an warning. These are messages returned by the input
   *  script.
   */
  void setWarningText(const QString& warn);

  /**
   * Show the warning text.
   */
  QString warningText() const;

  /**
   * Show the user an error message. These are errors that have occurred
   * in this extension, not necessarily in the input generator script.
   */
  void showError(const QString& err);

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
  void setFloatOption(const QString& name, const QJsonValue& value);
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
   * Update the autogenerated job title in the GUI.
   */
  QString generateJobTitle() const;

  QtGui::Molecule* m_molecule;
  QJsonObject m_options;
  QJsonObject m_optionCache; // For reverting changes
  QList<QTextEdit*> m_dirtyTextEdits;

  bool m_empty;
  QMap<QString, QWidget*> m_widgets;
  QMap<QString, QTextEdit*> m_textEdits;

  QtGui::InterfaceScript m_interfaceScript;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_INTERFACEWIDGET_H
