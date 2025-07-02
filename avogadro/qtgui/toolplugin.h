/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_TOOLPLUGIN_H
#define AVOGADRO_QTGUI_TOOLPLUGIN_H

#include "avogadroqtguiexport.h"

#include <QtCore/QObject>

class QAction;
class QKeyEvent;
class QMouseEvent;
class QUndoCommand;
class QWheelEvent;

namespace Avogadro {

namespace Rendering {
class GroupNode;
class GLRenderer;
} // namespace Rendering

namespace QtOpenGL {
class GLWidget;
}

namespace QtGui {
class Molecule;
class RWMolecule;

/**
 * @class ToolPlugin toolplugin.h <avogadro/qtgui/toolplugin.h>
 * @brief The base class for plugins that interact with QtOpenGL::GLWidget.
 * @author Allison Vacanti
 */
class AVOGADROQTGUI_EXPORT ToolPlugin : public QObject
{
  Q_OBJECT

public:
  explicit ToolPlugin(QObject* parent = nullptr);
  ~ToolPlugin() override;

  /**
   * The name of the tool, will be displayed in the user interface.
   */
  virtual QString name() const = 0;

  /**
   * A description of the tool, may be displayed in the user interface.
   */
  virtual QString description() const = 0;

  /**
   * A priority of the tool for sorting in the user interface.
   */
  virtual unsigned char priority() const = 0;

  /**
   * @return The QAction that will cause this tool to become active.
   */
  virtual QAction* activateAction() const = 0;

  /**
   * Set the tool icon (based on dark / light theme).
   */
  virtual void setIcon(bool darkTheme = false) = 0;

  /**
   * @return A QWidget that will be displayed to the user while this tool is
   * active.
   */
  virtual QWidget* toolWidget() const = 0;

  /**
   * Respond to user-input events.
   * @param e The QEvent object.
   * @return A QUndoCommand that can be used to undo any changes to the
   * molecule. If no undoable change is made, the method may return nullptr.
   * @{
   */
  virtual QUndoCommand* mousePressEvent(QMouseEvent* e);
  virtual QUndoCommand* mouseReleaseEvent(QMouseEvent* e);
  virtual QUndoCommand* mouseMoveEvent(QMouseEvent* e);
  virtual QUndoCommand* mouseDoubleClickEvent(QMouseEvent* e);
  virtual QUndoCommand* wheelEvent(QWheelEvent* e);
  virtual QUndoCommand* keyPressEvent(QKeyEvent* e);
  virtual QUndoCommand* keyReleaseEvent(QKeyEvent* e);
  /**@}*/

  /**
   * Override this method to add drawables to the scene graph.
   */
  virtual void draw(Rendering::GroupNode& node);

  /**
   * Called by the app to handle a command registered by the plugin.
   * (e.g., "renderMovie" or "drawAtom", etc.)
   *
   * The app will turn the command into a string and pass it to the tool.
   * and any options will go from a JSON dictionary to a QVariantMap.
   *
   * @return true if the command was handled, false otherwise.
   */
  virtual bool handleCommand(const QString& command,
                             const QVariantMap& options);

  /**
   * Called by the app to tell the tool to register commands.
   * If the tool has commands, it should emit the registerCommand signals.
   */
  virtual void registerCommands() {}

signals:
  /**
   * Emitted when draw() needs to be called again due to updates.
   */
  void drawablesChanged();

  /**
   * Emitted when something changed (camera, etc) and the molecule should be
   * redrawn.
   */
  void updateRequested();

  /**
   * Register a new command with the application. The command will be available
   * through scripting (e.g., "renderMovie" or "generateSurface", etc.)
   *
   * @param command The name of the command to register.
   * @param description A description of the command.
   *
   * @sa handleCommand
   */
  void registerCommand(QString command, QString description);

  /**
   * Request a specific display type (or types) are made active.
   * This can be useful when loading a specific type of data that
   * would be most readily viewed with a specialized view.
   */
  void requestActiveDisplayTypes(QStringList displayTypes);

public slots:
  /**
   * Called when the current molecule changes.
   */
  virtual void setMolecule(QtGui::Molecule* mol) = 0;
  virtual void setEditMolecule(QtGui::RWMolecule*) {}

  /**
   * Set the GLWidget used by the tool.
   */
  virtual void setGLWidget(QtOpenGL::GLWidget*) {}

  /**
   * Set the active widget used by the tool, this can be anything derived from
   * QWidget.
   */
  virtual void setActiveWidget(QWidget*) {}

  /**
   * Set the GLRenderer used by the tool.
   */
  virtual void setGLRenderer(Rendering::GLRenderer*) {}
};

/**
 * @class ToolPluginFactory toolplugin.h <avogadro/qtgui/toolplugin.h>
 * @brief The base class for tool plugin factories in Avogadro.
 * @author Allison Vacanti
 */
class AVOGADROQTGUI_EXPORT ToolPluginFactory
{
public:
  virtual ~ToolPluginFactory();

  virtual ToolPlugin* createInstance(QObject* parent = nullptr) = 0;
  virtual QString identifier() const = 0;
  virtual QString description() const = 0;
};

} // namespace QtGui
} // namespace Avogadro

Q_DECLARE_INTERFACE(Avogadro::QtGui::ToolPluginFactory,
                    "org.openchemistry.avogadro.ToolPluginFactory")

#endif // AVOGADRO_QTGUI_TOOLPLUGIN_H
