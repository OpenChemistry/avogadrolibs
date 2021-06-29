/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-13 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTOPENGL_GLWIDGET_H
#define AVOGADRO_QTOPENGL_GLWIDGET_H

#include "avogadroqtopenglexport.h"

#include <avogadro/qtgui/scenepluginmodel.h>
#include <avogadro/rendering/glrenderer.h>

#include <QtCore/QPointer>
#include <QtWidgets/QOpenGLWidget>

class QTimer;

namespace Avogadro {

namespace QtGui {
class Molecule;
class ToolPlugin;
}

namespace QtOpenGL {

/**
 * @class GLWidget glwidget.h <avogadro/qtopengl/glwidget.h>
 * @brief QOpenGLGLWidget derived object for displaying 3D molecular geometry.
 * @author Marcus D. Hanwell
 *
 * This class creates the GL context, and contains a renderer to render the
 * 3D molecular geometry.
 *
 * The GLWidget also manages a collection of ToolPlugins that are used to
 * respond to user input events. Use setTools() or addTool() to add tools to the
 * widget. Use setActiveTool() to indicate which tool is active. The active tool
 * will be given the opportunity to handle input events first. If the active
 * tool does not handle the event, the default tool will be used. If the default
 * tool also ignores the event, it will be passed to QOpenGLWidget's handlers.
 */

class AVOGADROQTOPENGL_EXPORT GLWidget : public QOpenGLWidget
{
  Q_OBJECT

public:
  explicit GLWidget(QWidget* parent = nullptr);
  ~GLWidget() override;

  /** Set the molecule the widget will render. */
  void setMolecule(QtGui::Molecule* molecule);

  /**
   * Get the molecule being rendered by the widget.
   * @{
   */
  QtGui::Molecule* molecule();
  const QtGui::Molecule* molecule() const;
  /** @}*/

  /** Get a reference to the renderer for the widget. */
  Rendering::GLRenderer& renderer() { return m_renderer; }

  /**
   * @return A list of the ToolPlugins owned by the GLWidget.
   */
  QList<QtGui::ToolPlugin*> tools() const { return m_tools; }

  /**
   * @return The active tool.
   */
  QtGui::ToolPlugin* activeTool() const { return m_activeTool; }

  /**
   * @return The default tool.
   */
  QtGui::ToolPlugin* defaultTool() const { return m_defaultTool; }

  /**
   * Get the GLWidget's ScenePluginModel, used to add, delete and modify the
   * scene plugin items.
   * @{
   */
  QtGui::ScenePluginModel& sceneModel() { return m_scenePlugins; }
  const QtGui::ScenePluginModel& sceneModel() const { return m_scenePlugins; }
  /** @}*/

  /**
   * Check if the GLWidget was able to acquire a context, and set up the
   * renderer correctly. If not valid, the error method may provide more
   * information.
   * @return true if value, false if not.
   */
  bool isValid() const { return m_renderer.isValid(); }

  /**
   * Get the error(s), if any, encountered when setting up the GLWidget.
   * @return A free form string containing errors encountered.
   */
  QString error() const { return m_renderer.error().c_str(); }

signals:
  void rendererInvalid();

public slots:
  /**
   * Update the scene plugins for the widget, this will generate geometry in
   * the scene etc.
   */
  void updateScene();

  /**
   * Clear the contents of the scene.
   */
  void clearScene();

  /** Reset the view to fit the entire scene. */
  void resetCamera();

  /** Reset the geometry when the molecule etc changes. */
  void resetGeometry();

  /**
   * Make the tools in toolList available to the GLWidget. The GLWidget takes
   * ownership of the tools.
   */
  void setTools(const QList<QtGui::ToolPlugin*>& toolList);

  /**
   * Make tool available to the GLWidget. The GLWidget takes ownership of the
   * tool.
   */
  void addTool(QtGui::ToolPlugin* tool);

  /**
   * Set the active tool. This is the tool that will be used to handle input
   * events first.
   * @{
   */
  void setActiveTool(const QString& name);
  void setActiveTool(QtGui::ToolPlugin* tool);
  /**@}*/

  /**
   * Set the default tool. This is the tool that will be used to handle input
   * events that are ignored by the active tool.
   * @{
   */
  void setDefaultTool(const QString& name);
  void setDefaultTool(QtGui::ToolPlugin* tool);
  /**@}*/

  /**
   * Request an update, this will by default initiate a timer that will trigger
   * in a specified time, enabling us to compress multiple events such as
   * camera moves to maintain interactivity.
   */
  void requestUpdate();

protected slots:
  /**
   * Perform the update of the render, this should only be called by the timer.
   */
  void updateTimeout();

protected:
  /** This is where the GL context is initialized. */
  void initializeGL() override;

  /** Take care of resizing the context. */
  void resizeGL(int width, int height) override;

  /** Main entry point for all GL rendering. */
  void paintGL() override;

  /** Reimplemented from QOpenGLWidget @{ */
  void mouseDoubleClickEvent(QMouseEvent*) override;
  void mousePressEvent(QMouseEvent*) override;
  void mouseMoveEvent(QMouseEvent*) override;
  void mouseReleaseEvent(QMouseEvent*) override;
  void wheelEvent(QWheelEvent*) override;
  void keyPressEvent(QKeyEvent*) override;
  void keyReleaseEvent(QKeyEvent*) override;
  /** @} */

private:
  QPointer<QtGui::Molecule> m_molecule;
  QList<QtGui::ToolPlugin*> m_tools;
  QtGui::ToolPlugin* m_activeTool;
  QtGui::ToolPlugin* m_defaultTool;
  Rendering::GLRenderer m_renderer;
  QtGui::ScenePluginModel m_scenePlugins;

  QTimer* m_renderTimer;
};

} // End QtOpenGL namespace
} // End Avogadro namespace

#endif // AVOGADRO_QTOPENGL_GLWIDGET_H
