/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

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

#include "editor.h"
#include "navigator.h"

#include <avogadro/rendering/glrenderer.h>
#include <avogadro/qtgui/scenepluginmodel.h>

#include <QtOpenGL/QGLWidget>

namespace Avogadro {
namespace QtOpenGL {

/*!
 * \class GLWidget glwidget.h <avogadro/rendering/glwidget.h>
 * \brief QGLWidget derived object for displaying 3D molecular geometry.
 * \author Marcus D. Hanwell
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

  /*! Get a reference to the editor for the widget. */
  Editor& editor() { return m_editor; }

  /*! Get a reference to the navigator for the widget. */
  Navigator& navigator() { return m_navigator; }

  /*! Get a reference to the renderer for the widget. */
  Rendering::GLRenderer& renderer() { return m_renderer; }

  /*! Reset the view to fit the entire scene. */
  void resetCamera();

protected:
  /*! This is where the GL context is initialized. */
  void initializeGL();

  /*! Take care of resizing the context. */
  void resizeGL(int width, int height);

  /*! Main entry point for all GL rendering. */
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
  Editor m_editor;
  Navigator m_navigator;
  Rendering::GLRenderer m_renderer;
  QtGui::ScenePluginModel m_scenePlugins;
};

} // End QtOpenGL namespace
} // End Avogadro namespace

#endif // AVOGADRO_QTOPENGL_GLWIDGET_H
