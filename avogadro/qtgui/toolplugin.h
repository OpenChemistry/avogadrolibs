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

namespace QtOpenGL {
class GLWidget;
}

namespace QtGui {
class Molecule;

/**
 * @class ToolPlugin toolplugin.h <avogadro/qtgui/toolplugin.h>
 * @brief The base class for plugins that interact with QtOpenGL::GLWidget.
 * @author David C. Lonie
 */
class AVOGADROQTGUI_EXPORT ToolPlugin : public QObject
{
  Q_OBJECT

public:
  explicit ToolPlugin(QObject *parent = 0);
  ~ToolPlugin();

  /**
   * The name of the tool, will be displayed in the user interface.
   */
  virtual QString name() const = 0;

  /**
   * A description of the tool, may be displayed in the user interface.
   */
  virtual QString description() const = 0;

  /**
   * @return The QAction that will cause this tool to become active.
   */
  virtual QAction * activateAction() const = 0;

  /**
   * @return A QWidget that will be displayed to the user while this tool is
   * active.
   */
  virtual QWidget * toolWidget() const = 0;

  /**
   * Respond to user-input events.
   * @param e The QEvent object.
   * @return A QUndoCommand that can be used to undo any changes to the
   * molecule. If no undoable change is made, the method may return NULL.
   * @{
   */
  virtual QUndoCommand * mousePressEvent(QMouseEvent *e);
  virtual QUndoCommand * mouseReleaseEvent(QMouseEvent *e);
  virtual QUndoCommand * mouseMoveEvent(QMouseEvent *e);
  virtual QUndoCommand * mouseDoubleClickEvent(QMouseEvent *e);
  virtual QUndoCommand * wheelEvent(QWheelEvent *e);
  virtual QUndoCommand * keyPressEvent(QKeyEvent *e);
  virtual QUndoCommand * keyReleaseEvent(QKeyEvent *e);
  /**@}*/

public slots:
  /**
   * Called when the current molecule changes.
   */
  virtual void setMolecule(QtGui::Molecule *mol) = 0;

  /**
   * Set the GLWidget used by the tool.
   */
  virtual void setGLWidget(QtOpenGL::GLWidget *widget) = 0;
};

/**
 * @class ToolPluginFactory toolplugin.h <avogadro/qtgui/toolplugin.h>
 * @brief The base class for tool plugin factories in Avogadro.
 * @author David C. Lonie
 */
class AVOGADROQTGUI_EXPORT ToolPluginFactory
{
public:
  virtual ~ToolPluginFactory();

  virtual ToolPlugin * createInstance() = 0;
  virtual QString identifier() const = 0;
};

} // End QtGui namespace
} // End Avogadro namespace

Q_DECLARE_INTERFACE(Avogadro::QtGui::ToolPluginFactory,
                    "net.openchemistry.avogadro.toolpluginfactory/2.0")

#endif // AVOGADRO_QTGUI_TOOLPLUGIN_H
