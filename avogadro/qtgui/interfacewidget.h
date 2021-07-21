/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_INTERFACEWIDGET_H
#define AVOGADRO_QTGUI_INTERFACEWIDGET_H

#include "avogadroqtguiexport.h"

#include <QtCore/QJsonObject>
#include <QtCore/QMap>
#include <QtWidgets/QWidget>

#include "interfacescript.h"
#include "jsonwidget.h"

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
class AVOGADROQTGUI_EXPORT InterfaceWidget : public JsonWidget
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
   * Access to the underlying input script object.
   */
  const QtGui::InterfaceScript& interfaceScript() const
  {
    return m_interfaceScript;
  }

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

  QtGui::Molecule* m_molecule;
  QtGui::InterfaceScript m_interfaceScript;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_INTERFACEWIDGET_H
