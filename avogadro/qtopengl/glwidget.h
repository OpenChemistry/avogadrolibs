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

#include <avogadro/rendering/glrenderer.h>
#include <avogadro/qtgui/scenepluginmodel.h>

#include <QtOpenGL/QGLWidget>

namespace Avogadro {

namespace QtGui {
class ToolPlugin;
}

namespace QtOpenGL {

/**
 * @class GLWidget glwidget.h <avogadro/rendering/glwidget.h>
 * @brief QGLWidget derived object for displaying 3D molecular geometry.
 * @author Marcus D. Hanwell
 *
 * This class creates the GL context, and contains a renderer to render the
 * 3D molecular geometry.
 */

class AVOGADROQTOPENGL_EXPORT GLWidget : public QGLWidget
{
  Q_OBJECT

public:
  explicit GLWidget(QWidget *parent = 0);
  ~GLWidget();

  /** Get a reference to the renderer for the widget. */
  Rendering::GLRenderer& renderer() { return m_renderer; }

  /// @todo Document these
  QList<QtGui::ToolPlugin*> tools() const { return m_tools; }

  QtGui::ToolPlugin * activeTool() const { return m_activeTool; }

  QtGui::ToolPlugin * defaultTool() const { return m_defaultTool; }

public slots:
  /** Reset the view to fit the entire scene. */
  void resetCamera();

  /// @todo Document these
  void setTools(QList<QtGui::ToolPlugin*> toolList) { m_tools = toolList; }

  void setActiveTool(const QString &name);
  void setActiveTool(QtGui::ToolPlugin* tool) { m_activeTool = tool; }

  void setDefaultTool(const QString &name);
  void setDefaultTool(QtGui::ToolPlugin* tool) { m_defaultTool = tool; }

protected:
  /** This is where the GL context is initialized. */
  void initializeGL();

  /** Take care of resizing the context. */
  void resizeGL(int width, int height);

  /** Main entry point for all GL rendering. */
  void paintGL();

protected:
  void mouseDoubleClickEvent(QMouseEvent *);
  void mousePressEvent(QMouseEvent *);
  void mouseMoveEvent(QMouseEvent *);
  void mouseReleaseEvent(QMouseEvent *);
  void wheelEvent(QWheelEvent *);
  void keyPressEvent(QKeyEvent *);
  void keyReleaseEvent(QKeyEvent *);

private:
  QList<QtGui::ToolPlugin*> m_tools;
  QtGui::ToolPlugin *m_activeTool;
  QtGui::ToolPlugin *m_defaultTool;
  Rendering::GLRenderer m_renderer;
  QtGui::ScenePluginModel m_scenePlugins;
};

} // End QtOpenGL namespace
} // End Avogadro namespace

#endif // AVOGADRO_QTOPENGL_GLWIDGET_H
