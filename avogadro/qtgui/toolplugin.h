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
}

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

  virtual ToolPlugin* createInstance(QObject *parent = nullptr) = 0;
  virtual QString identifier() const = 0;
};

} // End QtGui namespace
} // End Avogadro namespace

Q_DECLARE_INTERFACE(Avogadro::QtGui::ToolPluginFactory,
                    "org.openchemistry.avogadro.ToolPluginFactory")

#endif // AVOGADRO_QTGUI_TOOLPLUGIN_H
